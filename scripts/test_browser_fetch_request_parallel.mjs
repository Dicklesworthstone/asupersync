/** Actual mapper TypeScript, native Streams and loopback HTTP. Producer receipts
 * are explicit doubles except where another actual mapper owns the source.
 * node --experimental-vm-modules --test scripts/test_browser_fetch_request_parallel.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { createContext, SourceTextModule } from "node:vm";
const source = readFileSync(process.env.ASUPERSYNC_REQUEST_MAP_SOURCE
  ?? new URL("../packages/browser/src/fetch-request-map.ts", import.meta.url), "utf8");
console.log(JSON.stringify({ scenario: "bounded-parallel-request-mapping",
  sha256: createHash("sha256").update(source).digest("hex"),
  evidence: "actual mapper; native Streams/fetch; explicit producer receipts; no SDK task ABI" }));
const module = new SourceTextModule(stripTypeScriptTypes(source, { mode: "transform" }), {
  context: createContext({ ReadableStream, ReadableStreamDefaultReader, AbortController }),
});
await module.link(() => assert.fail("unexpected runtime dependency"));
await module.evaluate();
const api = module.namespace;
const ok = value => ({ outcome: "ok", value });
const err = message => ({ outcome: "err", failure: { code: "decode_failure", recoverability: "permanent", message } });
const panic = message => ({ outcome: "panicked", message });
const cancelled = () => ({ outcome: "cancelled", cancellation: { kind: "producer", phase: "completed",
  origin_region: "test-owner", origin_task: null, timestamp_nanos: 0, message: "retired", truncated: false } });
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
async function pending(promise) {
  let settled = false; void promise.then(() => { settled = true; }, () => { settled = true; });
  await turn(); assert.equal(settled, false, "barrier must remain pending");
}
const methods = ["mapFetchRequests", "tryMapFetchRequests", "flatMapFetchRequests", "tryFlatMapFetchRequests"];
function mapped(name, index) {
  const value = name.includes("Flat") || name.startsWith("flat") ? [{ url: `${index}/a` }, { url: `${index}/b` }] : { url: `${index}` };
  return name.startsWith("try") ? ok(value) : value;
}
function fixture(t, options = {}) {
  const gates = [], handles = [], readers = [], calls = { reads: 0, native: 0, owner: 0, mapped: [], signals: [] };
  const terminal = deferred(); let position = 0, controller;
  function gate() { const value = deferred(); gates.push(value); return value; }
  const readable = new ReadableStream({
    start(value) { controller = value; },
    pull(c) {
      calls.reads++;
      if (options.parkAfter !== undefined && position >= options.parkAfter) return;
      if (position < (options.count ?? 10)) c.enqueue(position++);
      else { c.close(); if (!options.holdTerminal) terminal.resolve(ok(undefined)); }
    },
    async cancel() { calls.native++; await options.nativeGate?.promise; },
  }, { highWaterMark: 0 });
  const owner = { readable, closed: terminal.promise, async cancel() {
    assert.equal(this, owner); calls.owner++;
    await options.ownerGate?.promise;
    if (!options.holdTerminal) terminal.resolve(cancelled());
    return ok(undefined);
  } };
  function start(name, mapper, config = {}, input = options.owned ? owner : readable) {
    const admitted = api[name](input, (value, index, signal) => {
      calls.mapped.push(index); calls.signals.push(signal); return mapper(value, index, signal);
    }, config);
    assert.equal(admitted.outcome, "ok"); handles.push(admitted.value); return admitted.value;
  }
  function reader(handle) { const value = handle.readable.getReader(); readers.push(value); return value; }
  function read(r) { const result = r.read(); void result.catch(() => {}); return result; }
  t.after(async () => {
    for (const g of gates) g.resolve(); options.nativeGate?.resolve(); options.ownerGate?.resolve(); terminal.resolve(ok(undefined));
    await Promise.all(handles.map(h => h.cancel("fixture cleanup")));
    for (const r of readers) { try { r.releaseLock(); } catch {} }
  });
  return { gate, start, reader, read, calls, readable, owner, terminal, controller };
}
for (const name of methods) for (const concurrency of [1, 2, 4, 64]) {
  test(`${name}: window ${concurrency} bounds blocked mappers AND completed reorder slots`, { timeout: 4000 }, async t => {
    const f = fixture(t, { count: concurrency + 3 });
    const gates = Array.from({ length: concurrency }, f.gate);
    const h = f.start(name, async (_value, index) => { await gates[index]?.promise; return mapped(name, index); }, { concurrency });
    const r = f.reader(h); await turn(); assert.equal(f.calls.reads, 0, "no demand means no source read");
    const first = f.read(r); await turn();
    assert.equal(f.calls.mapped.length, concurrency, "independent async mappers overlap");
    assert.equal(f.calls.reads, concurrency, "pending input reserves the same credit");
    for (let i = concurrency - 1; i > 0; i--) gates[i].resolve();
    await pending(first);
    assert.equal(f.calls.reads, concurrency, "completed out-of-order results retain their slots");
    gates[0].resolve(); const values = [(await first).value.url];
    await turn(); assert.equal(f.calls.reads, concurrency, "no read-ahead after output demand is satisfied");
    for (;;) { const item = await r.read(); if (item.done) break; values.push(item.value.url); }
    const expanded = name.includes("Flat") || name.startsWith("flat");
    assert.deepEqual(values, Array.from({ length: concurrency + 3 }, (_, i) => expanded ? [`${i}/a`, `${i}/b`] : [`${i}`]).flat());
    assert.equal((await h.closed).outcome, "ok"); assert.equal(f.readable.locked, false);
  });
}
for (const concurrency of [0, -1, 1.5, 65, NaN, Infinity, "2", null]) {
  test(`invalid parallelism ${String(concurrency)} refuses before ownership`, async t => {
    const f = fixture(t, { owned: true });
    for (const name of methods) assert.equal(api[name](f.owner, () => null, { concurrency }).outcome, "err");
    assert.equal(f.readable.locked, false); assert.equal(f.calls.reads, 0); assert.equal(f.calls.owner, 0);
  });
}
test("a pending later source read never blocks an earlier completed mapping", { timeout: 2000 }, async t => {
  const f = fixture(t, { parkAfter: 1 }); const release = f.gate();
  const h = f.start("mapFetchRequests", async () => { await release.promise; return { url: "ready" }; }, { concurrency: 2 });
  const r = f.reader(h), next = f.read(r); await turn(); assert.equal(f.calls.reads, 2);
  release.resolve(); assert.equal((await next).value.url, "ready");
  assert.equal((await h.cancel()).outcome, "cancelled"); assert.equal(f.calls.mapped.length, 1);
});
test("parallel cancellation joins each mapper plus all three producer barriers", { timeout: 2000 }, async t => {
  const nativeGate = deferred(), ownerGate = deferred();
  const f = fixture(t, { owned: true, holdTerminal: true, nativeGate, ownerGate });
  const gates = [f.gate(), f.gate(), f.gate()];
  const h = f.start("mapFetchRequests", async (_v, i) => { await gates[i].promise; return { url: `${i}` }; }, { concurrency: 3 });
  const r = f.reader(h), next = f.read(r); await turn(); assert.equal(f.calls.mapped.length, 3);
  const done = h.cancel("stop all"); assert.equal(done, h.cancel("second"));
  assert.ok(f.calls.signals.every(s => s.aborted)); await pending(done);
  assert.equal(f.calls.native, 1); assert.equal(f.calls.owner, 1);
  f.terminal.resolve(cancelled()); nativeGate.resolve(); ownerGate.resolve(); await pending(done);
  gates[1].resolve(); await pending(done); gates[0].resolve(); await pending(done); gates[2].resolve();
  assert.equal((await done).outcome, "cancelled"); await assert.rejects(next); assert.equal(f.readable.locked, false);
});
for (const returned of [false, true]) {
  test(`later-index ${returned ? "typed error" : "exception"} stops before the earlier mapper completes`, { timeout: 2000 }, async t => {
    const f = fixture(t), first = f.gate(), last = f.gate(), failNow = f.gate();
    const h = f.start(returned ? "tryMapFetchRequests" : "mapFetchRequests", async (_v, i) => {
      if (i === 1) { await failNow.promise; if (returned) return err("typed rejection"); throw new Error("private payload"); }
      await (i === 0 ? first : last).promise; return returned ? ok({ url: `${i}` }) : { url: `${i}` };
    }, { concurrency: 3 });
    const r = f.reader(h), next = f.read(r); await turn(); assert.equal(f.calls.mapped.length, 3); failNow.resolve();
    await pending(h.closed); assert.ok(f.calls.signals.every(s => s.aborted)); assert.equal(f.calls.native, 1);
    first.resolve(); await pending(h.closed); last.resolve(); const result = await h.closed;
    assert.equal(result.outcome, returned ? "err" : "panicked"); await assert.rejects(next);
    assert.equal(f.calls.reads, 3);
  });
}
test("late typed panic from another mapper strengthens cancellation", { timeout: 2000 }, async t => {
  const f = fixture(t), gates = [f.gate(), f.gate()];
  const h = f.start("tryMapFetchRequests", async (_v, i) => { await gates[i].promise; return i ? panic("late panic") : ok(null); }, { concurrency: 2 });
  const next = f.read(f.reader(h)); await turn(); assert.equal(f.calls.mapped.length, 2);
  void h.cancel(); gates[0].resolve(); await pending(h.closed); gates[1].resolve();
  assert.deepEqual(JSON.parse(JSON.stringify(await h.closed)), panic("late panic")); await assert.rejects(next);
});
test("synchronous cancellation from a later mapper cannot escape its join registration", { timeout: 2000 }, async t => {
  const f = fixture(t), gates = [f.gate(), f.gate()]; let h;
  h = f.start("mapFetchRequests", (_v, i) => { if (i === 1) void h.cancel(); return gates[i].promise; }, { concurrency: 2 });
  const next = f.read(f.reader(h)); await turn(); assert.equal(f.calls.mapped.length, 2);
  gates[0].resolve({ url: "late" }); await pending(h.closed); gates[1].resolve({ url: "later" });
  assert.equal((await h.closed).outcome, "cancelled"); await assert.rejects(next);
});
test("ready expansions behind a slow mapper are snapshotted and keep their slots", { timeout: 2000 }, async t => {
  const f = fixture(t, { count: 2 }), first = f.gate(); const expansion = [{ url: "original" }];
  const h = f.start("flatMapFetchRequests", async (_v, i) => { if (!i) { await first.promise; return []; } return expansion; }, { concurrency: 2 });
  const r = f.reader(h), next = f.read(r); await turn(); assert.equal(f.calls.mapped.length, 2);
  expansion[0] = { url: "replaced" }; first.resolve(); assert.equal((await next).value.url, "original");
  assert.equal((await r.read()).done, true); assert.equal((await h.closed).outcome, "ok");
});
test("parallel filtering preserves physical indices and exact-limit EOF", { timeout: 2000 }, async t => {
  const f = fixture(t, { count: 7 }), gate = f.gate();
  const h = f.start("tryMapFetchRequests", async (v, i) => { if (!i) await gate.promise; assert.equal(v, i); return ok(i % 2 ? null : { url: `${i}` }); }, { concurrency: 4, maxInputs: 7 });
  const r = f.reader(h), next = f.read(r); await turn(); gate.resolve(); const values = [(await next).value.url];
  for (;;) { const item = await r.read(); if (item.done) break; values.push(item.value.url); }
  assert.deepEqual(values, ["0", "2", "4", "6"]); assert.deepEqual(f.calls.mapped, [0, 1, 2, 3, 4, 5, 6]);
  assert.equal((await h.closed).outcome, "ok");
});
test("input limit rejects the excess record without mapping it, then joins admitted work", { timeout: 2000 }, async t => {
  const f = fixture(t, { count: 8 }), gates = [f.gate(), f.gate()];
  const h = f.start("mapFetchRequests", async (_v, i) => { await gates[i].promise; return { url: `${i}` }; }, { concurrency: 4, maxInputs: 2 });
  const next = f.read(f.reader(h)); await turn(); assert.deepEqual(f.calls.mapped, [0, 1]); assert.equal(f.calls.reads, 3);
  await pending(h.closed); gates.forEach(g => g.resolve()); assert.match((await h.closed).failure.message, /maxInputs/); await assert.rejects(next);
});
test("EOF with completed output still waits for the owned producer", { timeout: 2000 }, async t => {
  const f = fixture(t, { count: 2, owned: true, holdTerminal: true }), first = f.gate();
  const h = f.start("mapFetchRequests", async (_v, i) => { if (!i) await first.promise; return { url: `${i}` }; }, { concurrency: 4 });
  const r = f.reader(h), next = f.read(r); await turn(); assert.equal(f.calls.mapped.length, 2); first.resolve();
  assert.equal((await next).value.url, "0"); assert.equal((await r.read()).value.url, "1");
  const end = f.read(r); await pending(end); f.terminal.resolve(ok(undefined)); assert.equal((await end).done, true);
  assert.equal((await h.closed).outcome, "ok");
});
test("two actual parallel mapping stages propagate cancellation and join upstream work", { timeout: 2000 }, async t => {
  const f = fixture(t), gates = [f.gate(), f.gate(), f.gate()];
  const upstream = f.start("mapFetchRequests", async (_v, i) => { await gates[i].promise; return { url: `${i}` }; }, { concurrency: 3 });
  const admitted = api.mapFetchRequests(upstream, v => v, { concurrency: 2 }); assert.equal(admitted.outcome, "ok");
  const downstream = admitted.value; t.after(() => downstream.cancel());
  const r = downstream.readable.getReader(), next = r.read(); void next.catch(() => {});
  await turn(); assert.equal(f.calls.mapped.length, 3); void downstream.cancel(); await pending(downstream.closed);
  gates[1].resolve(); gates[2].resolve(); await pending(downstream.closed); gates[0].resolve();
  assert.equal((await downstream.closed).outcome, "cancelled"); assert.equal((await upstream.closed).outcome, "cancelled");
  await assert.rejects(next); r.releaseLock(); assert.equal(f.readable.locked, false); assert.equal(upstream.readable.locked, false);
});
test("real HTTP mappers overlap before responses and release results in input order", { timeout: 5000 }, async t => {
  const seen = [], responses = new Map();
  const server = createServer((request, response) => { const index = Number(request.url.slice(1)); seen.push(index); responses.set(index, response); });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const f = fixture(t, { count: 3 });
  const h = f.start("mapFetchRequests", async (_v, i, signal) => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/${i}`, { signal });
    return { url: await response.text() };
  }, { concurrency: 3 });
  t.after(async () => { void h.cancel(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const r = f.reader(h), next = f.read(r);
  // A finite host-side deadline guards a real three-request overlap witness.
  const until = Date.now() + 1500;
  while (seen.length < 3 && Date.now() < until) await new Promise(resolve => setTimeout(resolve, 5));
  assert.deepEqual([...seen].sort(), [0, 1, 2], "all requests reach server while every response is gated");
  responses.get(2).end("two"); responses.get(1).end("one"); await pending(next);
  responses.get(0).end("zero"); assert.equal((await next).value.url, "zero");
  assert.equal((await r.read()).value.url, "one"); assert.equal((await r.read()).value.url, "two");
  assert.equal((await r.read()).done, true); assert.equal((await h.closed).outcome, "ok");
});
