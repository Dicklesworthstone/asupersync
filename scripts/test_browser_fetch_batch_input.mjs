/** Actual batch TypeScript and native Streams/signals/fetch; scope/handle/task
 * receipts and the imported limit are explicit doubles, not full SDK evidence.
 * node --experimental-vm-modules --test scripts/test_browser_fetch_batch_input.mjs
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
console.log(JSON.stringify({ scenario_id: "fetch-batch-request-stream-input", source_sha256: createHash("sha256").update(source).digest("hex"),
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

for (const typed of [false, true]) for (const concurrency of [1, 2, 8, 64]) {
  test(`${typed ? "typed" : "value"} source pull/admission bound ${concurrency}`, { timeout: 5000 }, async t => {
    const f = fixture(t), input = requestSource(t);
    const batch = f.start(input.stream, item => typed ? ok(item.index) : item.index, { concurrency }, typed);
    assert.equal(input.stream.locked, true, "ownership is acquired synchronously");
    assert.equal(input.calls.pulls, 0, "no source pull in the setup call");
    assert.equal(f.calls.admit.length, 0);
    await pending(batch.closed);
    assert.equal(input.calls.pulls, concurrency);
    assert.equal(f.calls.admit.length, concurrency);
    assert.equal(f.calls.terminal.length, concurrency, "output waits still reserve input admission slots");
    const output = readerOf(batch.results);
    const first = await output.read();
    assert.equal(first.value.index, 0); assert.equal(first.value.value, 0);
    await turn();
    assert.equal(input.calls.pulls, concurrency + 1);
    assert.equal(f.calls.admit.length, concurrency + 1);
    await output.cancel();
    assert.equal((await batch.closed).outcome, "cancelled");
    assert.equal(input.calls.cancels, 1); assert.equal(input.stream.locked, false);
  });
}

test("unknown-length input drains thousands of requests with stable indices and without collecting inputs", { timeout: 10000 }, async t => {
  const count = 4097, f = fixture(t), input = requestSource(t, count);
  const batch = f.start(input.stream, async ({ index }) => index * 2, { concurrency: 4, maxRequests: count });
  const seen = new Set();
  for await (const item of batch.results) {
    assert.equal(item.value, item.index * 2); assert.equal(seen.has(item.index), false);
    seen.add(item.index);
    assert.ok(input.calls.pulls <= seen.size + 4, "source production remains bounded by delivered demand");
  }
  assert.equal(seen.size, count); assert.equal(input.calls.pulls, count + 1);
  assert.equal((await batch.closed).outcome, "ok");
  assert.equal(input.calls.cancels, 0); assert.equal(input.stream.locked, false);
});

test("one native request read at a time even with many idle workers", { timeout: 3000 }, async t => {
  let active = 0, maximum = 0, reads = 0;
  const proto = ReadableStreamDefaultReader.prototype;
  const closed = Object.getOwnPropertyDescriptor(proto, "closed").get;
  const traced = await load({ ReadableStreamDefaultReader: { prototype: {
    read() {
      reads++; active++; maximum = Math.max(maximum, active);
      return Reflect.apply(proto.read, this, []).finally(() => { active--; });
    },
    cancel: proto.cancel, releaseLock: proto.releaseLock,
    get closed() { return Reflect.apply(closed, this, []); },
  } } });
  const f = fixture(t), input = requestSource(t, 0, { park: true });
  const admitted = traced.streamMapFetches(f.scope, input.stream, () => 1, { concurrency: 16 });
  assert.equal(admitted.outcome, "ok"); t.after(() => admitted.value.cancel());
  await pending(admitted.value.closed);
  assert.equal(reads, 1); assert.equal(maximum, 1); assert.equal(active, 1);
  input.controller.enqueue({ url: "https://example.test/first" });
  await turn(); assert.equal(reads, 2); assert.equal(maximum, 1);
  assert.equal(f.calls.admit.length, 1);
  await admitted.value.cancel();
  assert.equal(active, 0); assert.equal(input.stream.locked, false);
});

for (const count of [0, 1, 3]) test(`native input EOF keeps all ${count} queued requests and pending results`, { timeout: 3000 }, async t => {
  const f = fixture(t);
  const source = new ReadableStream({ start(c) { for (const request of f.requests(count)) c.enqueue(request); c.close(); } });
  const batch = f.start(source, ({ index }) => index, { concurrency: 1 });
  const values = [];
  for await (const item of batch.results) values.push(item.value);
  assert.deepEqual(values, Array.from({ length: count }, (_, i) => i));
  assert.equal((await batch.closed).outcome, "ok"); assert.equal(source.locked, false);
});

test("pre-aborted input is cancelled without reading and cleanup gates settlement", { timeout: 3000 }, async t => {
  const f = fixture(t), gate = f.gate(), input = requestSource(t, Infinity, { cleanup: gate }), parent = new AbortController(); parent.abort();
  const batch = f.start(input.stream, () => assert.fail("consumer"), { signal: parent.signal });
  await pending(batch.closed); assert.equal(input.calls.pulls, 0); assert.equal(input.calls.cancels, 1);
  assert.equal(f.calls.admit.length, 0); assert.equal(input.stream.locked, true);
  gate.resolve(); assert.equal((await batch.closed).outcome, "cancelled"); assert.equal(input.stream.locked, false);
});

test("a native input is refused by collection APIs without taking ownership", async t => {
  const f = fixture(t), input = requestSource(t, 1);
  for (const method of [api.mapFetches, api.tryMapFetches]) {
    assert.equal(method(f.scope, input.stream, () => 1).outcome, "err");
    assert.equal(input.stream.locked, false);
  }
  assert.equal(input.calls.pulls, 0); assert.equal(input.calls.cancels, 0);
});

for (const maxRequests of [0, -1, 0.5, Infinity, NaN, Number.MAX_SAFE_INTEGER + 1, "3", null]) {
  test(`bad input maxRequests ${String(maxRequests)} refuses before ownership`, async t => {
    const f = fixture(t), input = requestSource(t, 1);
    assert.equal(api.streamMapFetches(f.scope, input.stream, () => 1, { maxRequests }).outcome, "err");
    assert.equal(input.stream.locked, false); assert.equal(input.calls.pulls, 0); assert.equal(input.calls.cancels, 0);
  });
}

test("invalid sources and locked input refuse without arbitrary method invocation", async t => {
  const f = fixture(t); let touched = 0;
  for (const input of [null, {}, { getReader() { touched++; throw 1; } }]) {
    assert.equal(api.streamMapFetches(f.scope, input, () => 1).outcome, "err");
  }
  const input = requestSource(t, 1), held = readerOf(input.stream);
  assert.equal(api.streamMapFetches(f.scope, input.stream, () => 1).outcome, "err");
  held.releaseLock(); assert.equal(input.calls.cancels, 0); assert.equal(touched, 0);
});

test("native input methods are captured intrinsics, not request-source overrides", { timeout: 3000 }, async t => {
  const f = fixture(t), input = requestSource(t); let touched = 0;
  input.stream.getReader = () => { touched++; throw 1; };
  input.stream.cancel = () => { touched++; throw 1; };
  const batch = f.start(input.stream); await turn(); await batch.cancel();
  assert.equal(touched, 0); assert.equal(input.calls.cancels, 1);
});

test("signal observer setup refusal releases input without pulling or cancelling", async t => {
  const rejected = await load({ EventTarget: { prototype: {
    addEventListener() { throw new Error("observer rejected"); }, removeEventListener() {},
  } } });
  const f = fixture(t), input = requestSource(t, 1);
  const admitted = rejected.streamMapFetches(f.scope, input.stream, () => 1, { signal: new AbortController().signal });
  assert.equal(admitted.outcome, "err"); assert.equal(input.stream.locked, false);
  await turn(); assert.equal(input.calls.pulls, 0); assert.equal(input.calls.cancels, 0);
});

test("source error while every output slot is backpressured stops and releases input", { timeout: 3000 }, async t => {
  const f = fixture(t), input = requestSource(t), batch = f.start(input.stream, undefined, { concurrency: 2 });
  await turn(); assert.equal(f.calls.terminal.length, 2);
  let inspected = 0;
  input.controller.error({ get cause() { inspected++; return panicked("forged"); }, toString() { inspected++; throw 1; } });
  const result = await batch.closed;
  assert.equal(result.outcome, "err"); assert.equal(result.failure.code, "internal_failure");
  assert.equal(inspected, 0); assert.equal(f.calls.admit.length, 2); assert.equal(input.stream.locked, false);
});

test("cancellation joins input cleanup, consumers, body cleanup and terminal publications independently", { timeout: 3000 }, async t => {
  const cleanup = [deferred(), deferred()], publication = [deferred(), deferred()];
  const f = fixture(t, { cleanup, publication }), inputCleanup = f.gate(), consumer = f.gate();
  const input = requestSource(t, 2, { park: true, cleanup: inputCleanup });
  const parent = new AbortController(), signals = [];
  const batch = f.start(input.stream, async item => { signals.push(item.signal); await consumer.promise; return item.index; }, { concurrency: 3, signal: parent.signal });
  await turn(); assert.equal(f.calls.consume.length, 2); assert.equal(input.calls.pulls, 3);
  parent.abort(); await pending(batch.closed);
  assert.equal(signals.every(s => s.aborted), true); assert.equal(input.calls.cancels, 1); assert.deepEqual(f.calls.cancel, [0, 1]);
  cleanup.forEach(g => g.resolve()); publication.forEach(g => g.resolve()); await pending(batch.closed);
  consumer.resolve(); await pending(batch.closed); assert.equal(input.stream.locked, true);
  inputCleanup.resolve(); assert.equal((await batch.closed).outcome, "cancelled");
  assert.equal(input.stream.locked, false); assert.equal(f.calls.admit.length, 2);
});

test("a request delivered concurrently with cancellation is never admitted or inspected", { timeout: 3000 }, async t => {
  const f = fixture(t), input = requestSource(t, 0, { park: true }), batch = f.start(input.stream); let touched = 0;
  await turn(); assert.equal(input.calls.pulls, 1);
  input.controller.enqueue({ get url() { touched++; throw 1; }, get body() { touched++; throw 1; } });
  const first = batch.cancel("race"); assert.equal(first, batch.cancel("again"));
  assert.equal((await first).outcome, "cancelled"); assert.equal(f.calls.admit.length, 0);
  assert.equal(touched, 0); assert.equal(input.calls.cancels, 1);
});

test("input beyond maxRequests refuses before scope admission and cancels the source", { timeout: 3000 }, async t => {
  const f = fixture(t), input = requestSource(t, 4), batch = f.start(input.stream, undefined, { concurrency: 1, maxRequests: 3 });
  const reader = readerOf(batch.results), prefix = [];
  for (let i = 0; i < 3; i++) prefix.push((await reader.read()).value.value);
  await assert.rejects(reader.read(), error => error.cause.outcome === "err" && /maxRequests/.test(error.cause.failure.message));
  assert.deepEqual(prefix, [0, 1, 2]); assert.equal(f.calls.admit.length, 3); assert.equal(input.calls.pulls, 4);
  assert.equal(input.calls.cancels, 1); assert.equal(input.stream.locked, false);
});

test("larger safe stream limits are accepted without allocating or eagerly reading that many entries", { timeout: 3000 }, async t => {
  const f = fixture(t), input = requestSource(t), batch = f.start(input.stream, undefined, { concurrency: 1, maxRequests: Number.MAX_SAFE_INTEGER });
  await turn(); assert.equal(input.calls.pulls, 1); await batch.cancel();
  assert.equal(input.stream.locked, false);
});

for (const kind of [err, cancelled, panicked]) test(`typed ${kind.name} joins source cancellation refusal without losing severity`, { timeout: 3000 }, async t => {
  const f = fixture(t), gate = f.gate(), input = requestSource(t, Infinity, { cleanup: gate, refuse: new Error("private cleanup payload") });
  const batch = f.start(input.stream, () => kind("consumer cause"), { concurrency: 1 }, true);
  await pending(batch.closed); assert.equal(input.calls.cancels, 1); gate.resolve();
  const result = await batch.closed;
  assert.equal(result.outcome, kind().outcome);
  if (result.outcome === "err") assert.match(result.failure.message, /source cancellation refused/);
  if (result.outcome === "panicked") assert.equal(result.message, "consumer cause");
  if (result.outcome === "cancelled") assert.equal(result.cancellation.message, "consumer cause");
  assert.equal(input.stream.locked, false);
});

test("normal output iteration break joins input cancellation before returning", { timeout: 3000 }, async t => {
  const f = fixture(t), gate = f.gate(), input = requestSource(t, Infinity, { cleanup: gate });
  const batch = f.start(input.stream, undefined, { concurrency: 2 });
  const loop = (async () => { for await (const _item of batch.results) break; })();
  await pending(loop); assert.equal(input.calls.cancels, 1); gate.resolve(); await loop;
  assert.equal((await batch.closed).outcome, "cancelled"); assert.equal(input.stream.locked, false);
});

test("downstream pipe failure retires request input as well as fetched bodies", { timeout: 3000 }, async t => {
  const f = fixture(t), input = requestSource(t), batch = f.start(input.stream, undefined, { concurrency: 2 });
  await assert.rejects(batch.results.pipeTo(new WritableStream({ write() { throw new Error("sink failed"); } })), /sink failed/);
  assert.equal((await batch.closed).outcome, "cancelled"); assert.equal(input.calls.cancels, 1);
  assert.equal(input.stream.locked, false); assert.ok(f.calls.admit.length <= 3);
});

test("real HTTP descriptor input stops its connection and active peer on early output exit", { timeout: 8000 }, async t => {
  const seen = [], sourceDisconnected = deferred(), peerDisconnected = deferred(), peerStarted = deferred();
  let origin;
  const server = createServer((request, response) => {
    seen.push(request.url);
    response.writeHead(200); response.flushHeaders();
    if (request.url === "/requests") {
      request.on("close", sourceDisconnected.resolve);
      response.write(JSON.stringify({ url: `${origin}/fast` }) + "\n" + JSON.stringify({ url: `${origin}/peer` }) + "\n");
    } else if (request.url === "/peer") {
      request.on("close", peerDisconnected.resolve); response.write("parked body"); peerStarted.resolve();
    } else {
      void peerStarted.promise.then(() => response.end("first value"));
    }
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
  const catalogController = new AbortController();
  const catalog = fetch(`${origin}/requests`, { signal: catalogController.signal });
  void catalog.catch(() => {}); // Also observed if a negative control refuses setup.
  let catalogReader, batch, pendingText = "", inputCancels = 0;
  const controllers = [], terminalReceipts = [];
  t.after(async () => {
    peerStarted.resolve(); catalogController.abort(); controllers.forEach(c => c.abort());
    server.closeAllConnections();
    if (batch) await batch.cancel();
    await new Promise(resolve => server.close(resolve));
  });
  const decoder = new TextDecoder();
  const input = new ReadableStream({
    async pull(target) {
      try {
        catalogReader ??= (await catalog).body.getReader();
        while (!pendingText.includes("\n")) {
          const item = await catalogReader.read();
          if (item.done) { target.close(); return; }
          pendingText += decoder.decode(item.value, { stream: true });
        }
        const end = pendingText.indexOf("\n"), line = pendingText.slice(0, end);
        pendingText = pendingText.slice(end + 1); target.enqueue(JSON.parse(line));
      } catch (error) { target.error(error); }
    },
    async cancel() {
      inputCancels++;
      try { catalogReader ??= (await catalog).body.getReader(); await catalogReader.cancel(); }
      finally { catalogController.abort(); }
    },
  }, { highWaterMark: 0 });
  const scope = { fetch(request) {
    const abort = new AbortController(), terminal = deferred(); controllers.push(abort); terminalReceipts.push(terminal.promise);
    const response = fetch(request.url, { signal: abort.signal }); let reader, retiring = false;
    const body = new ReadableStream({
      async pull(target) {
        try { reader ??= (await response).body.getReader(); const next = await reader.read();
          if (retiring) return;
          if (next.done) { target.close(); terminal.resolve(ok(undefined)); } else target.enqueue(next.value);
        } catch (error) { if (!retiring) { target.error(error); terminal.resolve(err("native read failed")); } }
      },
      async cancel() {
        retiring = true;
        try { reader ??= (await response).body.getReader(); await reader.cancel(); terminal.resolve(cancelled()); }
        catch { terminal.resolve(err("native cleanup failed")); } finally { abort.abort(); }
      },
    }, { highWaterMark: 0 });
    return ok({ closed: terminal.promise, toReadableStream: () => ok(body),
      response: () => response.then(r => ok({ status: r.status, statusText: r.statusText, url: r.url, headers: [...r.headers] })),
      cancel: () => body.cancel().then(() => ok(undefined)),
    });
  } };
  const admitted = api.streamMapFetches(scope, input, ({ body }) => new Response(body).text(), { concurrency: 2 });
  assert.equal(admitted.outcome, "ok"); batch = admitted.value;
  const output = [];
  for await (const item of batch.results) { output.push(item); break; }
  assert.equal(output.length, 1); assert.equal(output[0].index, 0); assert.equal(output[0].value, "first value");
  await Promise.all([sourceDisconnected.promise, peerDisconnected.promise]);
  assert.equal((await batch.closed).outcome, "cancelled"); assert.equal(inputCancels, 1);
  assert.equal(input.locked, false); assert.equal(terminalReceipts.length, 2);
  assert.deepEqual(seen.slice().sort(), ["/fast", "/peer", "/requests"]);
});
