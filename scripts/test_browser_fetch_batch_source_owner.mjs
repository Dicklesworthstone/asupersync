/** Actual batch TypeScript and native Streams/signals/fetch; scope/handle/task
 * receipts and the imported limit are explicit doubles, not full SDK evidence.
 * node --experimental-vm-modules --test scripts/test_browser_fetch_batch_source_owner.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";
const source = readFileSync(process.env.ASUPERSYNC_FETCH_BATCH_SOURCE
  ?? new URL("../packages/browser/src/fetch-batch.ts", import.meta.url), "utf8");
console.log(JSON.stringify({ scenario_id: "fetch-batch-owned-request-source", source_sha256: createHash("sha256").update(source).digest("hex"),
  evidence_scope: "actual batch; native Streams/signals/fetch; explicit scope/handle/terminal and limit doubles" }));
async function load(globals = {}) {
  const context = createContext({ ReadableStream, ReadableStreamDefaultReader, AbortController, AbortSignal, EventTarget, ...globals });
  const module = new SourceTextModule(stripTypeScriptTypes(source, { mode: "transform" }), { context });
  const limits = new SyntheticModule(["BROWSER_FETCH_LIMITS"], function () { this.setExport("BROWSER_FETCH_LIMITS", { maxRequestsPerRuntime: 64 }); }, { context });
  await module.link(name => { assert.equal(name, "./fetch.js"); return limits; });
  await module.evaluate(); return module.namespace;
}
const api = await load();
const ok = value => ({ outcome: "ok", value });
const err = (message = "application refused") => ({ outcome: "err", failure: { code: "decode_failure", recoverability: "permanent", message } });
const cancelled = (message = "normal retirement") => ({ outcome: "cancelled", cancellation: { kind: "test", phase: "completed",
  origin_region: "test", origin_task: null, timestamp_nanos: 0, message, truncated: false } });
const panicked = (message = "cleanup panic") => ({ outcome: "panicked", message });
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
async function pending(promise) {
  let done = false; void promise.then(() => { done = true; }, () => { done = true; });
  await turn(); assert.equal(done, false, "the witnessed cleanup/demand gate must still hold");
}
function readerOf(stream) { const reader = stream.getReader(); void reader.closed.catch(() => {}); return reader; }
function fixture(t, options = {}) {
  const calls = { admit: [], consume: [], cancel: [], terminal: [], pulls: [] }, pipelines = [], members = [], releases = [];
  const gate = () => { const value = deferred(); releases.push(value.resolve); return value; };
  const cleanup = options.cleanup ?? [], publication = options.publication ?? [];
  releases.push(...cleanup.map(g => g.resolve), ...publication.map(g => g.resolve));
  const scope = { fetch(request) {
    const index = calls.admit.length; calls.admit.push(request); options.onAdmit?.(index);
    const terminal = deferred(), headers = deferred(); let controller, sent = false, finished = false;
    function finish(outcome) { if (!finished) { finished = true; calls.terminal.push(index); terminal.resolve(outcome); } }
    const stream = new ReadableStream({
      start(value) { controller = value; },
      pull(target) {
        calls.pulls.push(index);
        if (!sent) { sent = true; target.enqueue(Uint8Array.of(index % 256)); }
        else { target.close(); finish(ok(undefined)); }
      },
      async cancel() {
        calls.cancel.push(index);
        headers.resolve(cancelled());
        await cleanup[index]?.promise;
        await publication[index]?.promise;
        finish(options.terminal?.[index] ?? cancelled());
        if (options.refuse?.[index]) throw new Error("cleanup refused");
      },
    }, { highWaterMark: 0 });
    if (!options.parkHeaders) headers.resolve(ok({ status: 200, statusText: "OK", url: request.url, headers: [] }));
    const handle = { closed: terminal.promise, response: () => headers.promise, toReadableStream: () => ok(stream),
      cancel: () => stream.cancel().then(() => ok(undefined)) };
    members.push({ stream, handle, fail(value) { controller.error(new Error("source stopped")); headers.resolve(value); finish(value); } });
    return ok(handle);
  } };
  const requests = count => Array.from({ length: count }, (_, i) => ({ url: `https://example.test/${i}` }));
  function start(input, consume = ({ index }) => index, config = {}, typed = false) {
    const admitted = (typed ? api.tryStreamMapFetches : api.streamMapFetches)(scope, input, item => {
      calls.consume.push(item.index); return consume(item);
    }, config);
    assert.equal(admitted.outcome, "ok"); pipelines.push(admitted.value); return admitted.value;
  }
  t.after(async () => { releases.forEach(release => release()); await Promise.all(pipelines.map(p => p.cancel("fixture cleanup"))); });
  return { calls, members, scope, requests, gate, start };
}

function requestSource(t, count = Infinity, options = {}) {
  let index = 0, controller;
  const calls = { pulls: 0, cancels: 0 };
  const stream = new ReadableStream({
    start(value) { controller = value; },
    pull(target) {
      calls.pulls++;
      if (index < count) target.enqueue({ url: `https://example.test/${index++}` });
      else if (!options.park) target.close();
    },
    async cancel() { calls.cancels++; await options.cleanup?.promise; if (options.refuse) throw options.refuse; },
  }, { highWaterMark: 0 });
  t.after(async () => { options.cleanup?.resolve(); if (!stream.locked) { try { await stream.cancel(); } catch {} } });
  return { stream, calls, controller };
}

function ownedSource(t, f, count = Infinity, options = {}) {
  const nativeCleanup = f.gate(), ownerReceipt = f.gate(), terminal = f.gate();
  const input = requestSource(t, count, { park: options.park, cleanup: nativeCleanup });
  const calls = { owner: 0 };
  const source = {
    readable: input.stream,
    closed: terminal.promise,
    cancel() { assert.equal(this, source, "source cancellation keeps its owner"); calls.owner++; return ownerReceipt.promise; },
  };
  const retire = (outcome = cancelled(), receipt = ok(undefined)) => {
    nativeCleanup.resolve(); ownerReceipt.resolve(receipt); terminal.resolve(outcome);
  };
  return { source, input, calls, nativeCleanup, ownerReceipt, terminal, retire };
}

for (const count of [0, 1, 3]) test(`owned producer completion gates native EOF for ${count} requests`, { timeout: 3000 }, async t => {
  const f = fixture(t), source = ownedSource(t, f, count), batch = f.start(source.source);
  const reader = readerOf(batch.results);
  for (let index = 0; index < count; index++) assert.equal((await reader.read()).value.value, index);
  const eof = reader.read(); await pending(eof); await pending(batch.closed);
  assert.equal(source.calls.owner, 0); assert.equal(source.input.stream.locked, true);
  source.terminal.resolve(ok(undefined));
  assert.equal((await eof).done, true); assert.equal((await batch.closed).outcome, "ok");
  assert.equal(source.input.stream.locked, false);
});

test("early successful producer receipt does not consume or discard queued requests", { timeout: 3000 }, async t => {
  const f = fixture(t), source = ownedSource(t, f, 3); source.terminal.resolve(ok(undefined));
  const batch = f.start(source.source, undefined, { concurrency: 1 }), values = [];
  for await (const item of batch.results) values.push(item.value);
  assert.deepEqual(values, [0, 1, 2]); assert.equal(source.calls.owner, 0);
  assert.equal((await batch.closed).outcome, "ok");
});

test("parent stop independently joins native cancellation, owner cancel and producer receipt", { timeout: 3000 }, async t => {
  const f = fixture(t), source = ownedSource(t, f, 0, { park: true }), parent = new AbortController();
  const batch = f.start(source.source, undefined, { signal: parent.signal });
  await turn(); assert.equal(source.input.calls.pulls, 1); parent.abort(); await pending(batch.closed);
  assert.equal(source.input.calls.cancels, 1); assert.equal(source.calls.owner, 1);
  source.terminal.resolve(cancelled()); await pending(batch.closed);
  source.nativeCleanup.resolve(); await pending(batch.closed);
  source.ownerReceipt.resolve(ok(undefined)); assert.equal((await batch.closed).outcome, "cancelled");
  assert.equal(source.input.stream.locked, false); assert.equal(f.calls.admit.length, 0);
});

test("producer terminal alone cannot complete a pending native cancellation barrier", { timeout: 3000 }, async t => {
  const f = fixture(t), source = ownedSource(t, f), batch = f.start(source.source);
  await turn(); const stop = batch.cancel();
  source.terminal.resolve(ok(undefined)); source.ownerReceipt.resolve(ok(undefined));
  await pending(stop); source.nativeCleanup.resolve(); await stop;
  assert.equal(source.calls.owner, 1);
});

for (const kind of [err, cancelled, panicked]) test(`idle owned ${kind.name} stops backpressured workers and preserves its typed reason`, { timeout: 3000 }, async t => {
  const f = fixture(t), source = ownedSource(t, f), batch = f.start(source.source, undefined, { concurrency: 2 });
  await turn(); assert.equal(f.calls.terminal.length, 2);
  source.terminal.resolve(kind("producer terminal")); await pending(batch.closed);
  assert.equal(source.calls.owner, 1); assert.equal(source.input.calls.cancels, 1);
  source.nativeCleanup.resolve(); source.ownerReceipt.resolve(ok(undefined));
  const result = await batch.closed;
  assert.equal(result.outcome, kind().outcome);
  const message = result.outcome === "err" ? result.failure.message : result.outcome === "cancelled" ? result.cancellation.message : result.message;
  assert.equal(message, "producer terminal"); assert.equal(f.calls.admit.length, 2);
});

test("source cancellation remains available after native EOF while its producer is still pending", { timeout: 3000 }, async t => {
  const f = fixture(t), source = ownedSource(t, f, 0), batch = f.start(source.source);
  await pending(batch.closed);
  const stop = batch.cancel("owner still running"); await pending(stop);
  assert.equal(source.calls.owner, 1); assert.equal(source.input.calls.cancels, 0, "native EOF is already closed");
  source.retire(); assert.equal((await stop).cancellation.message, "owner still running");
});

test("a request-stream error is replaced by its producer's authoritative cancellation, not an arbitrary cause", { timeout: 3000 }, async t => {
  const f = fixture(t), source = ownedSource(t, f, 0, { park: true }), batch = f.start(source.source);
  let inspected = 0; await turn();
  source.input.controller.error({ get cause() { inspected++; return panicked("forged"); } });
  await pending(batch.closed); assert.equal(source.calls.owner, 1);
  source.retire(cancelled("upstream scope closed"));
  const result = await batch.closed;
  assert.equal(result.outcome, "cancelled"); assert.equal(result.cancellation.message, "upstream scope closed");
  assert.equal(inspected, 0);
});

test("expected producer retirement cancellation does not replace a typed consumer error", { timeout: 3000 }, async t => {
  const f = fixture(t), source = ownedSource(t, f);
  const batch = f.start(source.source, () => err("application rejected"), { concurrency: 1 }, true);
  await pending(batch.closed); assert.equal(source.calls.owner, 1); source.retire(cancelled(), cancelled());
  const result = await batch.closed;
  assert.equal(result.outcome, "err"); assert.equal(result.failure.message, "application rejected");
});

for (const late of [err, panicked]) for (const origin of [err, cancelled, panicked]) {
  test(`${late.name} producer cleanup combines with ${origin.name} consumer using severity`, { timeout: 3000 }, async t => {
    const f = fixture(t), source = ownedSource(t, f);
    const batch = f.start(source.source, () => origin("consumer"), { concurrency: 1 }, true);
    await pending(batch.closed); source.retire(late("producer"));
    const result = await batch.closed;
    const keep = late === err && origin !== err;
    assert.equal(result.outcome, (keep ? origin : late)().outcome);
    const message = result.outcome === "err" ? result.failure.message : result.outcome === "cancelled" ? result.cancellation.message : result.message;
    assert.equal(message, keep ? "consumer" : "producer");
  });
}

test("owner cancellation panic outranks a successful producer terminal after caller abort", { timeout: 3000 }, async t => {
  const f = fixture(t), source = ownedSource(t, f), batch = f.start(source.source);
  await turn(); const stop = batch.cancel(); await pending(stop);
  source.retire(ok(undefined), panicked("cancel cleanup panic"));
  assert.equal((await stop).outcome, "panicked"); assert.equal((await batch.closed).message, "cancel cleanup panic");
});

for (const invalid of [null, 5, {}, { outcome: "err", failure: {} }, { outcome: "cancelled", cancellation: {} }]) {
  test(`malformed owned terminal ${JSON.stringify(invalid)} is not producer success`, { timeout: 3000 }, async t => {
    const f = fixture(t), source = ownedSource(t, f, 0), batch = f.start(source.source);
    source.retire(invalid);
    const result = await batch.closed;
    assert.equal(result.outcome, "err"); assert.equal(result.failure.code, "internal_failure");
  });
}

test("an undefined producer terminal is a malformed envelope rather than EOF", { timeout: 3000 }, async t => {
  const f = fixture(t), source = ownedSource(t, f, 0), batch = f.start(source.source);
  source.nativeCleanup.resolve(); source.ownerReceipt.resolve(ok(undefined)); source.terminal.resolve(undefined);
  const result = await batch.closed; assert.equal(result.outcome, "err"); assert.equal(result.failure.code, "internal_failure");
});

test("producer terminal rejection and owner callback throw are sanitized without presentation hooks", { timeout: 3000 }, async t => {
  const f = fixture(t), native = requestSource(t, 0); let inspected = 0;
  const thrown = { get cause() { inspected++; return panicked(); }, toString() { inspected++; return "private"; } };
  const source = { readable: native.stream, closed: Promise.reject(thrown), cancel() { throw thrown; } };
  const batch = f.start(source); const result = await batch.closed;
  assert.equal(result.outcome, "err"); assert.equal(result.failure.code, "internal_failure"); assert.equal(inspected, 0);
});

test("source properties are snapshotted before acquisition and cancellation keeps its original receiver", { timeout: 3000 }, async t => {
  const f = fixture(t), source = ownedSource(t, f); const originalCancel = source.source.cancel, originalClosed = source.source.closed;
  const reads = { cancel: 0, closed: 0, readable: 0 };
  Object.defineProperties(source.source, {
    cancel: { configurable: true, get() { reads.cancel++; return originalCancel; } },
    closed: { configurable: true, get() { reads.closed++; return originalClosed; } },
    readable: { configurable: true, get() { reads.readable++; return source.input.stream; } },
  });
  const batch = f.start(source.source);
  Object.defineProperty(source.source, "cancel", { value() { assert.fail("replacement cancellation"); } });
  Object.defineProperty(source.source, "closed", { value: Promise.resolve(panicked("unrelated replacement")) });
  const stop = batch.cancel(); source.retire(); assert.equal((await stop).outcome, "cancelled");
  assert.deepEqual(reads, { cancel: 1, closed: 1, readable: 1 }); assert.equal(source.calls.owner, 1);
});

test("producer panic messages are snapshotted once before stop callbacks", { timeout: 3000 }, async t => {
  const f = fixture(t), source = ownedSource(t, f), batch = f.start(source.source); let reads = 0;
  source.retire({ outcome: "panicked", get message() { reads++; return reads === 1 ? "original producer panic" : {}; } });
  const result = await batch.closed;
  assert.equal(result.outcome, "panicked"); assert.equal(result.message, "original producer panic"); assert.equal(reads, 1);
});

test("locked or malformed owned input refuses without invoking owner cleanup", async t => {
  const f = fixture(t), source = ownedSource(t, f), held = readerOf(source.input.stream);
  assert.equal(api.streamMapFetches(f.scope, source.source, () => 1).outcome, "err"); held.releaseLock();
  for (const closed of [null, 7, {}, { then: 4 }]) {
    assert.equal(api.streamMapFetches(f.scope, { ...source.source, closed }, () => 1).outcome, "err");
  }
  assert.equal(source.calls.owner, 0); assert.equal(source.input.calls.cancels, 0); assert.equal(source.input.stream.locked, false);
});

test("pre-aborted parent retires producer without request generation", { timeout: 3000 }, async t => {
  const f = fixture(t), source = ownedSource(t, f), parent = new AbortController(); parent.abort();
  const batch = f.start(source.source, undefined, { signal: parent.signal }); await pending(batch.closed);
  assert.equal(source.calls.owner, 1); assert.equal(source.input.calls.pulls, 0); assert.equal(f.calls.admit.length, 0);
  source.retire(); assert.equal((await batch.closed).outcome, "cancelled");
});

test("two actual batch stages preserve backpressure and retire their shared upstream producer", { timeout: 5000 }, async t => {
  const first = fixture(t), second = fixture(t), root = requestSource(t);
  const upstream = first.start(root.stream, ({ index }) => ({ url: `https://example.test/followup/${index}` }), { concurrency: 2 });
  const readable = upstream.results.pipeThrough(new TransformStream({ transform(item, controller) { controller.enqueue(item.value); } }), { preventCancel: false });
  const source = { readable, closed: upstream.closed, cancel: upstream.cancel };
  const downstream = second.start(source, ({ index }) => index, { concurrency: 2 });
  await pending(downstream.closed); assert.equal(second.calls.admit.length, 2);
  assert.ok(first.calls.admit.length <= 6, "both stages remain bounded while results are unread");
  for await (const item of downstream.results) { assert.equal(item.value, 0); break; }
  assert.equal((await downstream.closed).outcome, "cancelled"); assert.equal((await upstream.closed).outcome, "cancelled");
  assert.equal(root.calls.cancels, 1); assert.equal(root.stream.locked, false);
  assert.equal(readable.locked, false); assert.equal(first.members.every(m => !m.stream.locked), true);
  assert.equal(second.members.every(m => !m.stream.locked), true);
});

for (const receipt of [undefined, null, {}, { outcome: "err", failure: {} }]) {
  test(`bad owner cancellation receipt ${JSON.stringify(receipt)} cannot certify cleanup`, { timeout: 3000 }, async t => {
    const f = fixture(t), source = ownedSource(t, f), batch = f.start(source.source, () => err("application"), { concurrency: 1 }, true);
    await pending(batch.closed);
    source.nativeCleanup.resolve(); source.terminal.resolve(ok(undefined)); source.ownerReceipt.resolve(receipt);
    const result = await batch.closed;
    assert.equal(result.outcome, "err"); assert.equal(result.failure.code, "internal_failure");
    assert.equal(source.calls.owner, 1);
  });
}

test("producer envelope is copied before reentrant cancellation mutates it", { timeout: 3000 }, async t => {
  const f = fixture(t), source = ownedSource(t, f), envelope = err("original producer cause");
  const cancel = source.source.cancel;
  source.source.cancel = function () { envelope.failure.message = "mutated by callback"; return cancel.call(this); };
  const batch = f.start(source.source); source.terminal.resolve(envelope); await pending(batch.closed);
  assert.equal(envelope.failure.message, "mutated by callback");
  source.nativeCleanup.resolve(); source.ownerReceipt.resolve(ok(undefined));
  const result = await batch.closed;
  assert.equal(result.failure.message, "original producer cause"); assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.failure), true);
});

test("reentrant owner cancellation does not create a second source retirement", { timeout: 3000 }, async t => {
  const f = fixture(t), source = ownedSource(t, f); let batch;
  const original = source.source.cancel;
  source.source.cancel = function () { void batch.cancel("reentrant"); return original.call(this); };
  batch = f.start(source.source); const stop = batch.cancel("original"); await pending(stop);
  assert.equal(source.calls.owner, 1); assert.equal(source.input.calls.cancels, 1);
  source.retire(); assert.equal((await stop).cancellation.message, "original");
});

test("a real upstream batch failure reaches a second stage as its typed terminal Outcome", { timeout: 3000 }, async t => {
  const first = fixture(t), second = fixture(t), root = requestSource(t);
  const upstream = first.start(root.stream, () => err("upstream application failed"), { concurrency: 1 }, true);
  const readable = upstream.results.pipeThrough(new TransformStream({ transform(item, controller) { controller.enqueue(item.value); } }));
  const downstream = second.start({ readable, closed: upstream.closed, cancel: upstream.cancel });
  const result = await downstream.closed;
  assert.equal(result.outcome, "err"); assert.equal(result.failure.message, "upstream application failed");
  assert.equal(second.calls.admit.length, 0); assert.equal(root.calls.cancels, 1); assert.equal(readable.locked, false);
  assert.equal((await upstream.closed).failure.message, result.failure.message);
});
