/** Actual batch TypeScript and native Streams/signals/fetch; scope/handle/task
 * receipts and the imported limit are explicit doubles, not full SDK evidence.
 * node --experimental-vm-modules --test scripts/test_browser_fetch_batch_stream.mjs
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
console.log(JSON.stringify({ scenario_id: "fetch-batch-result-backpressure", source_sha256: createHash("sha256").update(source).digest("hex"),
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
  function start(consume = ({ index }) => index, config = {}, count = 8, typed = false) {
    const admitted = (typed ? api.tryStreamMapFetches : api.streamMapFetches)(scope, requests(count), item => {
      calls.consume.push(item.index); return consume(item);
    }, config);
    assert.equal(admitted.outcome, "ok"); pipelines.push(admitted.value); return admitted.value;
  }
  t.after(async () => { releases.forEach(release => release()); await Promise.all(pipelines.map(p => p.cancel("fixture cleanup"))); });
  return { calls, members, scope, requests, gate, start };
}

test("both streaming exports exist", () => {
  assert.equal(typeof api.streamMapFetches, "function"); assert.equal(typeof api.tryStreamMapFetches, "function");
});
for (const concurrency of [1, 2, 4, 64]) test(`result backpressure bounds admission at concurrency ${concurrency}`, { timeout: 5000 }, async t => {
  const f = fixture(t), stream = f.start(undefined, { concurrency }, concurrency + 5);
  await pending(stream.closed);
  assert.equal(f.calls.admit.length, concurrency);
  assert.equal(f.calls.terminal.length, concurrency, "finished bodies still occupy output-delivery slots");
  const reader = readerOf(stream.results);
  const first = await reader.read(); assert.equal(first.done, false); assert.equal(first.value.index, 0);
  assert.equal(Object.isFrozen(first.value), true);
  await turn(); assert.equal(f.calls.admit.length, concurrency + 1, "one output read releases one slot");
  await reader.cancel(); assert.equal((await stream.closed).outcome, "cancelled");
  assert.equal(f.calls.admit.length, concurrency + 1);
  assert.equal(f.members.every(m => !m.stream.locked), true);
});
test("completion order avoids head-of-line blocking and preserves input indexes", { timeout: 3000 }, async t => {
  const f = fixture(t), gate = f.gate(), ready = f.gate();
  const stream = f.start(async ({ index }) => { if (index === 0) { ready.resolve(); await gate.promise; } return `value-${index}`; }, { concurrency: 2 }, 4);
  const reader = readerOf(stream.results); await ready.promise;
  const second = await reader.read(); assert.equal(second.value.index, 1); assert.equal(second.value.value, "value-1");
  const third = await reader.read(); assert.equal(third.value.index, 2);
  gate.resolve(); const remaining = [await reader.read(), await reader.read()];
  assert.deepEqual(remaining.map(x => x.value.index).sort(), [0, 3]);
  assert.equal((await reader.read()).done, true); assert.equal((await stream.closed).outcome, "ok");
  assert.equal(f.calls.terminal.length, 4);
});
test("result is invisible until body cleanup AND terminal publication finish", { timeout: 3000 }, async t => {
  const cleanup = [deferred()], publication = [deferred()], f = fixture(t, { cleanup, publication });
  const stream = f.start(() => 42, { concurrency: 1 }, 1), reader = readerOf(stream.results), read = reader.read();
  await pending(read); assert.deepEqual(f.calls.cancel, [0]); assert.equal(f.calls.terminal.length, 0);
  cleanup[0].resolve(); await pending(read); publication[0].resolve();
  assert.equal((await read).value.value, 42); assert.equal((await reader.read()).done, true);
  assert.equal((await stream.closed).outcome, "ok");
});
test("manual cancellation drops unread results and releases every publication wait", { timeout: 3000 }, async t => {
  const f = fixture(t), stream = f.start(undefined, { concurrency: 3 }, 20);
  await turn(); assert.equal(f.calls.admit.length, 3); assert.equal(f.calls.terminal.length, 3);
  const first = stream.cancel("stop"), second = stream.cancel("ignored"); assert.equal(first, second);
  assert.equal((await first).cancellation.message, "stop"); assert.equal((await stream.closed).outcome, "cancelled");
  const reader = readerOf(stream.results);
  await assert.rejects(reader.read(), error => error.cause.outcome === "cancelled");
  assert.equal(f.calls.admit.length, 3);
});
test("parent abort releases backpressure without mutating its signal", { timeout: 3000 }, async t => {
  const f = fixture(t), parent = new AbortController(), stream = f.start(undefined, { signal: parent.signal, concurrency: 2 });
  await turn(); assert.equal(f.calls.terminal.length, 2);
  parent.abort({ toString() { assert.fail("do not render abort reason"); } });
  assert.equal((await stream.closed).outcome, "cancelled"); assert.equal(f.calls.admit.length, 2);
});
test("pre-aborted parent starts no requests; empty stream remains identity", { timeout: 3000 }, async t => {
  const f = fixture(t), parent = new AbortController(); parent.abort();
  const empty = f.start(undefined, { signal: parent.signal }, 0);
  assert.equal((await empty.closed).outcome, "ok"); assert.equal((await readerOf(empty.results).read()).done, true);
  const stopped = f.start(undefined, { signal: parent.signal }, 4);
  assert.equal((await stopped.closed).outcome, "cancelled"); assert.equal(f.calls.admit.length, 0);
});
test("pending result read observes the final failure only after consumer and cleanup drain", { timeout: 3000 }, async t => {
  const cleanup = [deferred(), deferred()], f = fixture(t, { cleanup });
  const ready = f.gate(), release = f.gate();
  const stream = f.start(async item => { if (item.index === 0) { await ready.promise; return err("ordinary"); }
    ready.resolve(); await release.promise; return panicked("late consumer panic"); }, { concurrency: 2 }, 3, true);
  const reader = readerOf(stream.results), read = reader.read(); void read.catch(() => {});
  await pending(read); assert.deepEqual(f.calls.cancel, [0, 1]);
  cleanup.forEach(g => g.resolve()); await pending(read); release.resolve();
  await assert.rejects(read, error => error.cause.outcome === "panicked" && error.cause.message === "late consumer panic");
  assert.equal((await stream.closed).message, "late consumer panic"); assert.equal(f.calls.admit.length, 2);
});
test("native cancel closure is distinct from its full cleanup promise", { timeout: 3000 }, async t => {
  const cleanup = [deferred()], f = fixture(t, { cleanup, parkHeaders: true });
  const stream = f.start(undefined, { concurrency: 1 }), reader = readerOf(stream.results), read = reader.read();
  await turn(); assert.equal(f.calls.admit.length, 1);
  const cancellation = reader.cancel({ get cause() { assert.fail("do not inspect native reasons"); } });
  assert.equal((await read).done, true, "native stream closes immediately on cancel");
  await pending(cancellation); await pending(stream.closed); cleanup[0].resolve();
  await cancellation; assert.equal((await stream.closed).outcome, "cancelled");
});
test("breaking async iteration joins sibling consumers and their cleanup", { timeout: 3000 }, async t => {
  const cleanup = [deferred(), deferred()], f = fixture(t, { cleanup });
  const release = f.gate(), started = f.gate();
  const stream = f.start(async ({ index, signal }) => { if (index === 1) { started.resolve(); await release.promise; assert.equal(signal.aborted, true); } return index; }, { concurrency: 2 }, 4);
  const loop = (async () => { for await (const item of stream.results) { assert.equal(item.index, 0); break; } })();
  await started.promise; cleanup[0].resolve(); await pending(loop);
  assert.equal(f.calls.admit.length <= 3, true); release.resolve(); await pending(loop);
  cleanup[1].resolve(); await loop; assert.equal((await stream.closed).outcome, "cancelled");
});
test("pipeTo sink failure cancels and drains the batch", { timeout: 3000 }, async t => {
  const f = fixture(t), stream = f.start(undefined, { concurrency: 2 }, 20), sentinel = new Error("sink failed");
  await assert.rejects(stream.results.pipeTo(new WritableStream({ write() { throw sentinel; } })), error => error === sentinel);
  assert.equal((await stream.closed).outcome, "cancelled"); assert.equal(f.calls.admit.length <= 3, true);
  assert.equal(f.calls.terminal.length, f.calls.admit.length);
});
test("cleanup panic rejects result-stream cancellation after the drain", { timeout: 3000 }, async t => {
  const gate = deferred(), f = fixture(t, { cleanup: [gate], terminal: [panicked()] });
  const stream = f.start(undefined, { concurrency: 1 }); await turn(); assert.deepEqual(f.calls.cancel, [0]);
  const cancellation = stream.results.cancel(); void cancellation.catch(() => {}); await pending(cancellation);
  gate.resolve(); await assert.rejects(cancellation, error => error.cause.outcome === "panicked");
  assert.equal((await stream.closed).outcome, "panicked");
});
test("a delivered prefix survives a later typed failure, but unread results do not escape", { timeout: 3000 }, async t => {
  const f = fixture(t), stream = f.start(({ index }) => index === 1 ? err("second failed") : ok(index), { concurrency: 1 }, 3, true);
  const reader = readerOf(stream.results);
  assert.equal((await reader.read()).value.value, 0);
  await assert.rejects(reader.read(), error => error.cause.failure.message === "second failed");
  assert.equal((await stream.closed).outcome, "err"); assert.equal(f.calls.admit.length, 2);
});
test("typed stream unwraps values without assimilating nested thenables", { timeout: 3000 }, async t => {
  const f = fixture(t); let assimilated = 0; const value = { then() { assimilated++; }, payload: [1] };
  const stream = f.start(() => ok(value), {}, 1, true), reader = readerOf(stream.results);
  const item = (await reader.read()).value; assert.equal(item.value, value); assert.equal(assimilated, 0);
  assert.equal(Object.isFrozen(value), false); assert.equal((await reader.read()).done, true);
});
test("untyped stream preserves Outcome-shaped values as data", { timeout: 3000 }, async t => {
  const f = fixture(t), value = err("not a stop"), stream = f.start(() => value, {}, 2), output = [];
  for await (const item of stream.results) output.push(item.value);
  assert.deepEqual(output, [value, value]); assert.equal((await stream.closed).outcome, "ok");
});
test("reader lock release preserves an in-flight result for a replacement reader", { timeout: 3000 }, async t => {
  const f = fixture(t), gate = f.gate(), started = f.gate();
  const stream = f.start(async () => { started.resolve(); await gate.promise; return 99; }, { concurrency: 1 }, 1);
  const reader = readerOf(stream.results), read = reader.read(); void read.catch(() => {});
  await started.promise; reader.releaseLock(); await assert.rejects(read); gate.resolve(); await turn();
  const replacement = readerOf(stream.results); assert.equal((await replacement.read()).value.value, 99);
  assert.equal((await replacement.read()).done, true); assert.equal((await stream.closed).outcome, "ok");
});
test("typed and untyped array collection stay input ordered and do not wait for output demand", { timeout: 3000 }, async t => {
  const f = fixture(t);
  for (const typed of [false, true]) {
    const admitted = (typed ? api.tryMapFetches : api.mapFetches)(f.scope, f.requests(129), ({ index }) => typed ? ok(index) : index, { concurrency: 3 });
    assert.equal(admitted.outcome, "ok"); const result = await admitted.value.result;
    assert.equal(result.outcome, "ok"); assert.deepEqual(Array.from(result.value), Array.from({ length: 129 }, (_, i) => i));
  }
});
test("invalid stream options and callbacks refuse before admission", async t => {
  const f = fixture(t);
  for (const concurrency of [0, 65, 1.5, NaN]) assert.equal(api.streamMapFetches(f.scope, f.requests(2), () => 1, { concurrency }).outcome, "err");
  assert.equal(api.tryStreamMapFetches(f.scope, f.requests(2), null).outcome, "err");
  const restricted = await load({ ReadableStream: undefined });
  assert.equal(restricted.streamMapFetches(f.scope, [], () => 1).outcome, "err");
  assert.equal(f.calls.admit.length, 0);
});
test("incremental output then early break disconnects a real HTTP peer and fences queued requests", { timeout: 5000 }, async t => {
  const seen = [], peerStarted = deferred(), peerClosed = deferred();
  const server = createServer((request, response) => {
    seen.push(request.url); response.writeHead(200); response.flushHeaders();
    if (request.url === "/first") response.end("first payload");
    else { request.on("close", peerClosed.resolve); response.write("peer prefix"); peerStarted.resolve(); }
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  let pipeline; const controllers = [], terminals = [];
  t.after(async () => { controllers.forEach(c => c.abort()); server.closeAllConnections(); if (pipeline) await pipeline.cancel(); await new Promise(resolve => server.close(resolve)); });
  const scope = { fetch(request) {
    const controller = new AbortController(), terminal = deferred(); controllers.push(controller);
    terminals.push(terminal.promise);
    const response = fetch(request.url, { signal: controller.signal }); let reader;
    const body = new ReadableStream({
      async pull(target) { try { reader ??= (await response).body.getReader(); const item = await reader.read();
        if (item.done) { target.close(); terminal.resolve(ok(undefined)); } else target.enqueue(item.value);
      } catch (error) { target.error(error); terminal.resolve(cancelled()); } },
      async cancel() { controller.abort(); try { if (reader) await reader.cancel(); await response.catch(() => {}); }
        finally { terminal.resolve(cancelled()); } },
    }, { highWaterMark: 0 });
    return ok({ closed: terminal.promise, response: () => response.then(value => ok({ status: value.status, statusText: value.statusText, url: value.url, headers: [] }), () => cancelled()),
      toReadableStream: () => ok(body) });
  } };
  const origin = `http://127.0.0.1:${server.address().port}`;
  const admitted = api.streamMapFetches(scope, ["/first", "/peer", "/queued", "/never"].map(path => ({ url: origin + path })),
    async ({ index, body }) => { if (index === 0) { await peerStarted.promise; return new Response(body).text(); }
      return new Response(body).text(); }, { concurrency: 2 });
  assert.equal(admitted.outcome, "ok"); pipeline = admitted.value;
  for await (const item of pipeline.results) { assert.equal(item.index, 0); assert.equal(item.value, "first payload"); break; }
  assert.equal((await pipeline.closed).outcome, "cancelled"); await peerClosed.promise;
  assert.equal(seen.includes("/never"), false); assert.ok(controllers.length <= 3);
  assert.equal(controllers.slice(1).every(c => c.signal.aborted), true);
  assert.deepEqual((await Promise.all(terminals)).map(value => value.outcome), ["ok", ...controllers.slice(1).map(() => "cancelled")]);
});
