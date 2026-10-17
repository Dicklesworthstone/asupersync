/** Actual batch TypeScript and native Streams/signals/fetch; explicit scope and
 * terminal-receipt doubles. Not full SDK task-ABI or Rust/WASM evidence.
 * node --experimental-vm-modules --test scripts/test_browser_fetch_batch_outcomes.mjs
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
console.log(JSON.stringify({ scenario_id: "fetch-batch-typed-consumers", source_sha256: createHash("sha256").update(source).digest("hex"),
  evidence_scope: "actual batch; native Streams/signals/fetch; explicit scope/handle/terminal and request-limit doubles" }));
const context = createContext({ ReadableStream, ReadableStreamDefaultReader, AbortController, AbortSignal, EventTarget });
const module = new SourceTextModule(stripTypeScriptTypes(source, { mode: "transform" }), { context });
const limits = new SyntheticModule(["BROWSER_FETCH_LIMITS"], function () {
  this.setExport("BROWSER_FETCH_LIMITS", Object.freeze({ maxRequestsPerRuntime: 64 }));
}, { context });
await module.link(name => { assert.equal(name, "./fetch.js"); return limits; });
await module.evaluate();
const api = module.namespace;
// The pre-feature control runs the SAME consumer contract against mapFetches,
// not a simulated scheduler. A separate test asserts the new export exists.
const tryMap = api.tryMapFetches ?? api.mapFetches;
const ok = value => ({ outcome: "ok", value });
const err = (message = "application error") => ({ outcome: "err", failure: { code: "decode_failure", recoverability: "permanent", message } });
const cancelled = (message = "consumer cancelled") => ({ outcome: "cancelled", cancellation: { kind: "consumer_stop", phase: "completed",
  origin_region: "consumer-owner", origin_task: "consumer-task", timestamp_nanos: 7n, message, truncated: false } });
const panicked = (message = "consumer panic") => ({ outcome: "panicked", message });
const message = value => value.outcome === "err" ? value.failure.message
  : value.outcome === "cancelled" ? value.cancellation.message : value.message;
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
async function pending(promise) { let done = false; void promise.then(() => { done = true; }); await turn(); assert.equal(done, false); }

function fixture(t, options = {}) {
  const calls = { admit: [], cancel: [], terminal: [], consume: [] }, batches = [], members = [];
  const releases = [...(options.cleanup ?? []), ...(options.publication ?? [])].map(gate => gate.resolve);
  const gate = () => { const result = deferred(); releases.push(result.resolve); return result; };
  const scope = { fetch(request) {
    const index = calls.admit.length; calls.admit.push(request);
    const completion = deferred(); let sent = false;
    const stream = new ReadableStream({
      pull(controller) { if (!sent) { sent = true; controller.enqueue(Uint8Array.of(index % 256)); }
        else { controller.close(); finish(ok(undefined)); } },
      async cancel() {
        calls.cancel.push(index); options.onCancel?.(index);
        await options.cleanup?.[index]?.promise;
        await options.publication?.[index]?.promise;
        finish(options.terminal?.[index] ?? cancelled("normal retirement"));
        if (options.refuse?.[index]) throw new Error("cancel refused");
      },
    }, { highWaterMark: 0 });
    function finish(outcome) { if (!calls.terminal.includes(index)) calls.terminal.push(index); completion.resolve(outcome); }
    const handle = { closed: completion.promise, response: () => Promise.resolve(ok({ status: 200, statusText: "OK", url: request.url, headers: [] })),
      toReadableStream: () => ok(stream), cancel: () => stream.cancel().then(() => ok(undefined)) };
    members.push({ handle, stream }); return ok(handle);
  } };
  const requests = count => Array.from({ length: count }, (_, index) => ({ url: `https://example.test/${index}` }));
  const start = (consume, config, count = 5, legacy = false) => {
    const admitted = (legacy ? api.mapFetches : tryMap)(scope, requests(count), item => {
      calls.consume.push(item.index); return consume(item);
    }, config);
    assert.equal(admitted.outcome, "ok"); batches.push(admitted.value); return admitted.value;
  };
  t.after(async () => { for (const release of releases) release(); await Promise.all(batches.map(batch => batch.cancel("fixture cleanup"))); });
  return { calls, members, scope, start, requests, gate };
}

test("tryMapFetches is exported", () => assert.equal(typeof api.tryMapFetches, "function"));
test("typed successes unwrap in input order across bounded out-of-order consumers", { timeout: 2000 }, async t => {
  const f = fixture(t), release = f.gate(), started = f.gate();
  const batch = f.start(async ({ index }) => { if (index === 0) { started.resolve(); await release.promise; } return ok(index); }, { concurrency: 2 }, 129);
  await started.promise; await pending(batch.result);
  assert.equal(f.calls.admit.length, 129); assert.equal(f.calls.terminal.length, 128);
  release.resolve(); const result = await batch.result;
  assert.equal(result.outcome, "ok"); assert.deepEqual(Array.from(result.value), Array.from({ length: 129 }, (_, i) => i));
  assert.equal(Object.isFrozen(result.value), true); assert.equal(f.calls.terminal.length, 129);
});
for (const kind of [err, cancelled, panicked]) {
  test(`returned ${kind.name} fences queued work, aborts siblings and waits for consumers AND cleanup`, { timeout: 2000 }, async t => {
    const cleanup = [deferred(), deferred()], publication = [deferred(), deferred()];
    const f = fixture(t, { cleanup, publication });
    const ready = f.gate(), decide = f.gate(), lingering = f.gate(); let signal;
    const batch = f.start(async item => {
      if (item.index === 0) { await decide.promise; return kind("explicit consumer cause"); }
      signal = item.signal; ready.resolve(); await lingering.promise; return ok(9);
    }, { concurrency: 2 });
    await ready.promise; decide.resolve(); await turn();
    // The fixture releases every host gate even when the old-code control fails.
    assert.equal(signal.aborted, true);
    assert.deepEqual(f.calls.cancel, [0, 1]); assert.equal(f.calls.admit.length, 2);
    await pending(batch.result); cleanup.forEach(g => g.resolve()); await pending(batch.result);
    publication.forEach(g => g.resolve()); await pending(batch.result);
    lingering.resolve(); const result = await batch.result;
    assert.equal(result.outcome, kind().outcome); assert.equal(message(result), "explicit consumer cause");
    assert.equal(f.calls.terminal.length, 2); assert.equal(f.members.every(m => !m.stream.locked), true);
  });
}
for (const invalid of [undefined, null, 7, {}, { outcome: "ok-ish" }, { outcome: "err", failure: {} }, { outcome: "cancelled", cancellation: {} }]) {
  test(`malformed returned Outcome ${JSON.stringify(invalid)} fails closed`, { timeout: 2000 }, async t => {
    const f = fixture(t); const result = await f.start(() => invalid, { concurrency: 1 }).result;
    assert.equal(result.outcome, "err"); assert.equal(result.failure.code, "internal_failure");
    assert.equal(f.calls.admit.length, 1); assert.equal(f.calls.terminal.length, 1);
  });
}
test("throwing envelope accessors fail closed without leaking exception presentation", { timeout: 2000 }, async t => {
  const f = fixture(t); let rendered = 0;
  const result = await f.start(() => ({ get outcome() { throw { toString() { rendered++; return "private"; } }; } }), { concurrency: 1 }).result;
  assert.equal(result.outcome, "err"); assert.equal(result.failure.code, "internal_failure"); assert.equal(rendered, 0);
});
for (const reject of [false, true]) {
  test(`actual ${reject ? "rejection" : "throw"} remains a sanitized panic and never reads cause`, { timeout: 2000 }, async t => {
    const f = fixture(t); let inspected = 0;
    const thrown = { get cause() { inspected++; return err(); }, toString() { inspected++; return "secret"; } };
    const batch = f.start(() => { if (reject) return Promise.reject(thrown); throw thrown; }, { concurrency: 1 });
    const result = await batch.result;
    assert.equal(result.outcome, "panicked"); assert.equal(result.message, "fetch batch consumer threw or rejected"); assert.equal(inspected, 0);
    assert.equal(f.calls.admit.length, 1);
  });
}
test("returned failure is copied before reentrant consumer-abort callbacks mutate its envelope", { timeout: 2000 }, async t => {
  const envelope = err("original cause"); const f = fixture(t); const ready = f.gate(), go = f.gate();
  let peerSignal;
  const batch = f.start(async item => {
    if (item.index === 0) { await go.promise; return envelope; }
    peerSignal = item.signal;
    return new Promise(resolve => { item.signal.addEventListener("abort", () => {
      envelope.failure.message = "mutated"; resolve(ok(undefined));
    }, { once: true }); ready.resolve(); });
  }, { concurrency: 2 });
  await ready.promise; go.resolve(); await turn(); assert.equal(peerSignal.aborted, true);
  const result = await batch.result;
  assert.equal(result.outcome, "err"); assert.equal(result.failure.message, "original cause");
  assert.equal(Object.isFrozen(result), true); assert.equal(Object.isFrozen(result.failure), true);
});
test("a nested success value retains identity without thenable assimilation or deep freezing", { timeout: 2000 }, async t => {
  let calls = 0; const value = { then() { calls++; }, data: [7] }; const f = fixture(t);
  const result = await f.start(() => ok(value), { concurrency: 1 }, 1).result;
  assert.equal(result.outcome, "ok"); assert.equal(result.value[0], value); assert.equal(calls, 0);
  assert.equal(Object.isFrozen(value), false); value.data.push(8);
});
test("legacy mapFetches still treats Outcome-shaped values as ordinary data", { timeout: 2000 }, async t => {
  const f = fixture(t), value = err("data, not stop");
  const result = await f.start(() => value, { concurrency: 1 }, 3, true).result;
  assert.equal(result.outcome, "ok"); assert.equal(result.value.length, 3);
  for (const item of result.value) assert.equal(item, value);
  assert.equal(f.calls.admit.length, 3);
});
test("legacy mapFetches never inspects an Outcome tag on an ordinary object", { timeout: 2000 }, async t => {
  const f = fixture(t); let reads = 0; const value = { get outcome() { reads++; throw new Error("not an envelope"); } };
  const result = await f.start(() => value, {}, 1, true).result;
  assert.equal(result.value[0], value); assert.equal(reads, 0);
});
for (const late of [err, cancelled, panicked]) {
  test(`late ${late.name} consumer result participates in cancellation drain severity`, { timeout: 2000 }, async t => {
    const f = fixture(t), started = f.gate(), release = f.gate(); const parent = new AbortController();
    const batch = f.start(async () => { started.resolve(); await release.promise; return late("late consumer"); }, { signal: parent.signal }, 1);
    await started.promise; parent.abort(); await pending(batch.result); release.resolve();
    const result = await batch.result;
    assert.equal(result.outcome, late === panicked ? "panicked" : "cancelled");
    assert.equal(message(result), late === panicked ? "late consumer" : "fetch batch cancelled by signal");
  });
}
for (const origin of [err, cancelled, panicked]) {
  for (const cleanup of [err, panicked]) {
    test(`${origin.name} consumer and ${cleanup.name} cleanup choose stronger Outcome`, { timeout: 2000 }, async t => {
      const f = fixture(t, { terminal: [cleanup("cleanup")] });
      const result = await f.start(() => origin("consumer"), { concurrency: 1 }, 1).result;
      const keepConsumer = origin === panicked && cleanup === err || origin === cancelled && cleanup === err;
      assert.equal(result.outcome, (keepConsumer ? origin : cleanup)().outcome);
      assert.equal(message(result), keepConsumer ? "consumer" : "cleanup");
    });
  }
}
test("pre-aborted parent invokes neither scope nor typed consumer; empty input remains identity", { timeout: 2000 }, async t => {
  const f = fixture(t), parent = new AbortController(); parent.abort();
  const batch = f.start(() => assert.fail("consumer must not run"), { signal: parent.signal });
  assert.equal((await batch.result).outcome, "cancelled"); assert.equal(f.calls.admit.length, 0);
  const empty = f.start(() => assert.fail("empty consumer"), { signal: parent.signal }, 0);
  assert.equal((await empty.result).outcome, "ok");
});
test("invalid typed callback and configuration are refused before scope effects", async t => {
  const f = fixture(t);
  for (const callback of [null, undefined, 1, {}]) assert.equal(tryMap(f.scope, f.requests(1), callback).outcome, "err");
  for (const concurrency of [0, 65, 1.5]) assert.equal(tryMap(f.scope, f.requests(1), () => ok(1), { concurrency }).outcome, "err");
  assert.equal(f.calls.admit.length, 0);
});
test("consumer rethrow of an owned body failure retains transport error rather than becoming a panic", { timeout: 2000 }, async t => {
  const f = fixture(t, { terminal: [err("publication failure")] });
  const result = await f.start(async ({ body }) => { await body.cancel(); return ok(undefined); }, {}, 1).result;
  assert.equal(result.outcome, "err"); assert.equal(message(result), "publication failure");
});
test("typed HTTP rejection cancels real unread bodies and fences queued requests", { timeout: 5000 }, async t => {
  const seen = [], disconnected = deferred(), peerStarted = deferred();
  const server = createServer((request, response) => {
    seen.push(request.url); response.writeHead(request.url === "/bad" ? 503 : 200); response.flushHeaders();
    response.write("body prefix");
    if (request.url === "/peer") { request.on("close", disconnected.resolve); peerStarted.resolve(); }
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  let batch; const controllers = [], terminals = [];
  t.after(async () => { controllers.forEach(c => c.abort()); server.closeAllConnections(); if (batch) await batch.cancel(); await new Promise(resolve => server.close(resolve)); });
  const scope = { fetch(request) {
    const controller = new AbortController(), done = deferred(); controllers.push(controller); terminals.push(done.promise);
    const response = fetch(request.url, { signal: controller.signal }); let reader;
    const body = new ReadableStream({
      async pull(target) { try { reader ??= (await response).body.getReader(); const item = await reader.read();
        if (item.done) { target.close(); done.resolve(ok(undefined)); } else target.enqueue(item.value);
      } catch (error) { target.error(error); done.resolve(err("host read failure")); } },
      async cancel() { try { reader ??= (await response).body.getReader(); await reader.cancel(); done.resolve(cancelled("host retired")); }
        catch { done.resolve(err("host cleanup failure")); } finally { controller.abort(); } },
    }, { highWaterMark: 0 });
    return ok({ closed: done.promise, toReadableStream: () => ok(body), response: () => response.then(value => ok({ status: value.status,
      statusText: value.statusText, url: value.url, headers: [...value.headers] })) });
  } };
  const base = `http://127.0.0.1:${server.address().port}`;
  const result = tryMap(scope, ["/bad", "/peer", "/never"].map(path => ({ url: base + path })), async ({ response }) => {
    await peerStarted.promise;
    return response.status === 503 ? err("HTTP 503 rejected by application") : ok(response.status);
  }, { concurrency: 2 });
  assert.equal(result.outcome, "ok"); batch = result.value;
  const terminal = await batch.result; assert.equal(terminal.outcome, "err");
  assert.equal(message(terminal), "HTTP 503 rejected by application");
  await disconnected.promise; assert.deepEqual(seen.sort(), ["/bad", "/peer"]);
  assert.equal(terminals.length, 2); await Promise.all(terminals);
});
