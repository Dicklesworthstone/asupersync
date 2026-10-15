/** Native Streams tests of the actual selection source with explicit fetch-handle
 * and terminal-receipt doubles. The loopback test uses real HTTP and native fetch.
 * This is not an SDK task-ABI or Rust/WASM integration proof.
 * Run: node --experimental-vm-modules --test scripts/test_browser_fetch_selection.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { getEventListeners } from "node:events";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { createContext, SourceTextModule } from "node:vm";
const source = readFileSync(process.env.ASUPERSYNC_FETCH_SELECTION_SOURCE
  ?? new URL("../packages/browser/src/fetch-selection.ts", import.meta.url), "utf8");
const code = stripTypeScriptTypes(source, { mode: "transform" });
console.log(JSON.stringify({ scenario_id: "browser-fetch-selection", source_sha256: createHash("sha256").update(source).digest("hex"),
  evidence_scope: "actual selection module; native Streams; explicit fetch handles/receipts; real loopback HTTP" }));
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const ok = (value) => ({ outcome: "ok", value });
const err = (message) => ({ outcome: "err", failure: { code: "internal_failure", recoverability: "unknown", message } });
const cancelled = (message = "cancelled") => ({ outcome: "cancelled", cancellation: { kind: "test_cancel", phase: "completed",
  origin_region: "explicit-test-owner", origin_task: null, timestamp_nanos: 0, message, truncated: false } });
const head = (status = 200, headers = []) => ({ status, statusText: "", url: "https://example.test/", headers });
const turn = () => new Promise((resolve) => setImmediate(resolve));
async function pending(promise) { let done = false; void promise.then(() => { done = true; }, () => { done = true; }); await turn(); assert.equal(done, false); }
async function api(globals = {}) {
  const module = new SourceTextModule(code, { context: createContext({ ReadableStream, ReadableStreamDefaultReader, AbortSignal, EventTarget, ...globals }) });
  await module.link(() => { throw new Error("selection unexpectedly added a runtime dependency"); });
  await module.evaluate(); return module.namespace;
}
const methods = await api();
function select(list, required = 1, options) {
  const result = methods.quorumFetchResponses(list.map((member) => member.handle ?? member), required, options);
  assert.equal(result.outcome, "ok"); return result.value;
}
function member(t, options = {}) {
  const headers = deferred(), completion = deferred();
  const count = { pulls: 0, cancels: 0, conversions: 0, responses: 0 };
  let controller, sent = false;
  const stream = new ReadableStream({
    start(value) { controller = value; },
    pull(value) {
      count.pulls += 1;
      if (!sent) { sent = true; value.enqueue(Uint8Array.of(options.byte ?? 7)); }
      else { value.close(); completion.resolve(ok(undefined)); }
    },
    async cancel() {
      count.cancels += 1;
      await options.cleanup;
      completion.resolve(options.terminal ?? cancelled());
      if (options.refuse) throw new Error("cancel refused");
    },
  }, { highWaterMark: 0 });
  const handle = { closed: completion.promise,
    response() { count.responses += 1; return headers.promise; },
    toReadableStream() { count.conversions += 1; return ok(stream); },
  };
  t.after(async () => {
    options.release?.();
    if (!stream.locked) { try { await stream.cancel(); } catch {} }
  });
  return { handle, stream, count, completion,
    respond(value = head()) { headers.resolve(ok(value)); },
    responseFailure(value = err("transport failed")) { headers.resolve(value); completion.resolve(value); controller.error(new Error("source failed")); },
    sourceFailure(value = err("selected body failed")) { completion.resolve(value); controller.error(new Error("source failed")); },
  };
}

for (const [members, required] of [[[], 1], [null, 1], [{}, 1], [[{}], 0], [[{}], -1], [[{}], 1.5], [[{}], 2], [new Array(65).fill({}), 1]]) {
  test(`invalid selection shape ${typeof members}/${members?.length}/${required}`, () => {
    assert.equal(methods.quorumFetchResponses(members, required).outcome, "err");
  });
}
test("invalid predicate and options refuse before conversion", async (t) => {
  const a = member(t);
  for (const options of [{ accept: 7 }, null]) assert.equal(methods.quorumFetchResponses([a.handle], 1, options).outcome, "err");
  assert.equal(a.count.conversions, 0);
});
test("duplicate handles refuse before body transfer", async (t) => {
  const a = member(t); assert.equal(methods.quorumFetchResponses([a.handle, a.handle], 1).outcome, "err");
  assert.equal(a.count.conversions, 0); assert.equal(a.count.cancels, 0);
});
test("locked second body rolls back the first lock without cancellation", async (t) => {
  const a = member(t), b = member(t); const held = b.stream.getReader();
  assert.equal(methods.quorumFetchResponses([a.handle, b.handle], 1).outcome, "err");
  assert.equal(a.stream.locked, false); assert.equal(a.count.cancels, 0); held.releaseLock();
});
test("aliased body rolls back its acquired reader", async (t) => {
  const a = member(t), alias = { ...a.handle };
  assert.equal(methods.quorumFetchResponses([a.handle, alias], 1).outcome, "err");
  assert.equal(a.stream.locked, false); assert.equal(a.count.cancels, 0);
});
test("missing native readers refuses without taking ownership", async (t) => {
  const restricted = await api({ ReadableStreamDefaultReader: undefined }); const a = member(t);
  assert.equal(restricted.quorumFetchResponses([a.handle], 1).outcome, "err"); assert.equal(a.count.conversions, 0);
});
test("first acceptable response rejects fast HTTP failures and transfers an unread body", async (t) => {
  const a = member(t), b = member(t, { byte: 19 }); a.respond(head(503));
  const group = methods.firstAcceptableFetchResponse([a.handle, b.handle]); assert.equal(group.outcome, "ok");
  await pending(group.value.result); assert.equal(a.count.cancels, 1); b.respond(head(201));
  const won = await group.value.result;
  assert.equal(won.outcome, "ok"); assert.equal(won.value.index, 1); assert.equal(b.count.pulls, 0);
  assert.equal(won.value.fetch, b.handle); assert.equal(won.value.body, b.stream); assert.equal(b.stream.locked, false);
  assert.deepEqual(Array.from(new Uint8Array(await new Response(won.value.body).arrayBuffer())), [19]);
  assert.equal((await b.handle.closed).outcome, "ok");
});
test("quorum chooses by observation order but returns selected members in input order", async (t) => {
  const list = [member(t), member(t), member(t)]; const group = select(list, 2);
  list[2].respond(); await pending(group.result); list[0].respond();
  const won = await group.result; assert.equal(won.outcome, "ok");
  assert.deepEqual(Array.from(won.value, (value) => value.index), [0, 2]);
  assert.equal(list[1].count.cancels, 1); assert.equal(list[0].count.cancels, 0); assert.equal(list[2].count.cancels, 0);
});
test("already-ready ties follow input order and excess accepted bodies are retired", async (t) => {
  const list = [member(t), member(t), member(t)]; for (const item of list) item.respond();
  const result = await select(list, 2).result; assert.equal(result.outcome, "ok");
  assert.deepEqual(Array.from(result.value, (value) => value.index), [0, 1]); assert.equal(list[2].count.cancels, 1);
});
test("all-member quorum transfers every body without cancelling or reading", async (t) => {
  const list = [member(t), member(t)]; for (const item of list) item.respond();
  const result = await select(list, 2).result; assert.equal(result.outcome, "ok");
  for (const item of list) { assert.equal(item.count.cancels, 0); assert.equal(item.count.pulls, 0); }
});
test("impossible quorum cancels still-parked headers immediately", async (t) => {
  const list = [member(t), member(t), member(t)]; const group = select(list, 3); list[0].respond(head(404));
  const result = await group.result; assert.equal(result.outcome, "err"); assert.match(result.failure.message, /quorum/);
  assert.deepEqual(list.map((item) => item.count.cancels), [1, 1, 1]);
});
test("a rejected member begins cleanup before any quorum can be formed", async (t) => {
  const a = member(t), b = member(t); const group = select([a, b]); a.respond(head(404));
  await pending(group.result); assert.equal(a.count.cancels, 1); assert.equal(b.count.cancels, 0);
  await group.cancel();
});
test("success waits for every slow loser cleanup in parallel", async (t) => {
  const gates = [deferred(), deferred()]; const a = member(t), b = member(t, { cleanup: gates[0].promise, release: gates[0].resolve }),
    c = member(t, { cleanup: gates[1].promise, release: gates[1].resolve });
  a.respond(); const group = select([a, b, c]); await pending(group.result);
  assert.equal(b.count.cancels, 1); assert.equal(c.count.cancels, 1); assert.equal(a.stream.locked, true);
  gates[0].resolve(); await pending(group.result); gates[1].resolve(); assert.equal((await group.result).outcome, "ok");
});
test("cancellation during loser drain retires the proposed winner too", async (t) => {
  const gate = deferred(); const a = member(t), b = member(t, { cleanup: gate.promise, release: gate.resolve }); a.respond();
  const group = select([a, b]); await pending(group.result); const cancelledResult = group.cancel("during cleanup");
  await pending(cancelledResult); assert.equal(a.count.cancels, 1); gate.resolve();
  const result = await group.result; assert.equal(result.outcome, "cancelled"); assert.equal(result.cancellation.message, "during cleanup");
});
test("cancel is idempotent while all response headers are parked", async (t) => {
  const a = member(t), b = member(t); const group = select([a, b]);
  const first = group.cancel("first"), second = group.cancel("second"); assert.equal(first, second);
  const result = await first; assert.equal(result.outcome, "cancelled"); assert.equal(result.cancellation.message, "first");
  assert.equal(a.count.cancels, 1); assert.equal(b.count.cancels, 1);
});
test("invalid cancel reason preserves pending work", async (t) => {
  const a = member(t); const group = select([a]); assert.equal((await group.cancel({})).outcome, "err");
  assert.equal(a.count.cancels, 0); await group.cancel();
});
test("cancel after successful transfer is inert", async (t) => {
  const a = member(t); a.respond(); const group = select([a]); assert.equal((await group.result).outcome, "ok");
  assert.equal((await group.cancel()).outcome, "ok"); assert.equal(a.count.cancels, 0);
});
test("selected body failure during drain prevents dead-body delivery", async (t) => {
  const gate = deferred(); const a = member(t), b = member(t, { cleanup: gate.promise, release: gate.resolve }); a.respond();
  const group = select([a, b]); await pending(group.result); a.sourceFailure(err("winner-reset")); gate.resolve();
  const result = await group.result; assert.equal(result.outcome, "err"); assert.match(result.failure.message, /winner-reset/);
});
test("transport failure is not hidden as an ordinary HTTP rejection", async (t) => {
  const a = member(t), b = member(t); const group = select([a, b]); a.responseFailure(err("transport-failed"));
  const result = await group.result; assert.equal(result.outcome, "err"); assert.match(result.failure.message, /transport-failed/);
  assert.equal(b.count.cancels, 1);
});
test("owner cancellation while waiting for quorum cancels all siblings", async (t) => {
  const a = member(t), b = member(t); a.respond(); const group = select([a, b], 2); await pending(group.result);
  a.sourceFailure(cancelled("scope closed")); assert.equal((await group.result).outcome, "cancelled"); assert.equal(b.count.cancels, 1);
});
test("cancel refusal with an otherwise successful receipt fails closed", async (t) => {
  const a = member(t), b = member(t, { refuse: true, terminal: ok(undefined) }); a.respond();
  const result = await select([a, b]).result; assert.equal(result.outcome, "err"); assert.match(result.failure.message, /refused/);
  assert.equal(a.count.cancels, 1);
});
test("terminal publication failure retires the selected body without waiting for other slow losers", async (t) => {
  const gate = deferred(); const a = member(t), b = member(t, { terminal: err("publication-refused") }),
    c = member(t, { cleanup: gate.promise, release: gate.resolve }); a.respond(); const group = select([a, b, c]);
  await pending(group.result); assert.equal(a.count.cancels, 1); gate.resolve();
  assert.match((await group.result).failure.message, /publication-refused/);
});
test("cleanup panic outranks errors regardless of completion timing", async (t) => {
  const gate = deferred(); const a = member(t), b = member(t, { terminal: err("ordinary") }),
    c = member(t, { cleanup: gate.promise, release: gate.resolve, terminal: { outcome: "panicked", message: "cleanup-panic" } });
  a.respond(); const group = select([a, b, c]); await pending(group.result); gate.resolve();
  const result = await group.result; assert.equal(result.outcome, "panicked"); assert.equal(result.message, "cleanup-panic");
});
test("same-severity cleanup failures use input order", async (t) => {
  const gate = deferred(); const a = member(t), b = member(t, { cleanup: gate.promise, release: gate.resolve, terminal: err("first-index") }),
    c = member(t, { terminal: err("second-index") }); a.respond(); const group = select([a, b, c]);
  await pending(group.result); gate.resolve(); assert.equal((await group.result).failure.message, "first-index");
});
test("predicate sees bounded frozen snapshots, not mutable caller metadata", async (t) => {
  const a = member(t); const metadata = head(409, [["x-replica", "ready"]]); let snapshot;
  const group = select([a], 1, { accept(value, index) { snapshot = value; assert.equal(index, 0);
    assert.equal(Object.isFrozen(value), true); assert.equal(Object.isFrozen(value.headers[0]), true);
    return value.headers[0][1] === "ready"; } }); a.respond(metadata);
  const result = await group.result; metadata.headers[0][1] = "changed";
  assert.equal(result.outcome, "ok"); assert.equal(snapshot.headers[0][1], "ready"); assert.equal(result.value[0].response.status, 409);
});
test("predicate exception cannot forge an Outcome through cause or presentation hooks", async (t) => {
  const a = member(t), b = member(t); let touched = 0; a.respond();
  const thrown = { get cause() { touched += 1; return ok(undefined); }, toString() { touched += 1; return "secret"; } };
  const result = await select([a, b], 1, { accept() { throw thrown; } }).result;
  assert.equal(result.outcome, "err"); assert.equal(touched, 0); assert.equal(a.count.cancels, 1); assert.equal(b.count.cancels, 1);
});
test("async predicate is refused and its rejection is observed", async (t) => {
  const a = member(t); a.respond(); const result = await select([a], 1, { accept: async () => { throw new Error("secret"); } }).result;
  assert.equal(result.outcome, "err"); assert.doesNotMatch(result.failure.message, /secret/); await turn();
});
test("predicate reentrant cancellation cannot publish success", async (t) => {
  const a = member(t); let group; group = select([a], 1, { accept() { void group.cancel("in predicate"); return true; } }); a.respond();
  assert.equal((await group.result).outcome, "cancelled"); assert.equal(a.count.cancels, 1);
});
for (const metadata of [null, head(NaN), head(200, new Array(129).fill(["x", "y"])), head(200, [["x", "z".repeat(65537)]])]) {
  test("malformed or oversized metadata fails closed and drains", async (t) => {
    const a = member(t); a.respond(metadata); assert.equal((await select([a]).result).outcome, "err"); assert.equal(a.count.cancels, 1);
  });
}
test("malformed terminal receipt is not success", async (t) => {
  const a = member(t), b = member(t, { terminal: { outcome: "unknown" } }); a.respond();
  assert.equal((await select([a, b]).result).outcome, "err"); assert.equal(a.count.cancels, 1);
});
test("sixty-four members reach an exact quorum without read-ahead", async (t) => {
  const list = Array.from({ length: 64 }, () => member(t)); for (const item of list) item.respond();
  const result = await select(list, 32).result; assert.equal(result.outcome, "ok"); assert.equal(result.value.length, 32);
  assert.equal(list.reduce((sum, item) => sum + item.count.cancels, 0), 32); assert.equal(list.reduce((sum, item) => sum + item.count.pulls, 0), 0);
});
test("real HTTP selection rejects 503, drains its connection and returns 200 body", { timeout: 5000 }, async (t) => {
  const disconnected = deferred();
  const server = createServer((request, response) => {
    response.writeHead(request.url === "/bad" ? 503 : 200, { "Content-Type": "text/plain" }); response.flushHeaders();
    if (request.url === "/bad") { request.on("close", disconnected.resolve); response.write("not selected"); }
    else response.end("chosen payload");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); });
  function httpMember(path) {
    const controller = new AbortController(); const closed = deferred(); let nativeReader;
    const response = fetch(`http://127.0.0.1:${server.address().port}${path}`, { signal: controller.signal });
    const body = new ReadableStream({
      async pull(target) { try { nativeReader ??= (await response).body.getReader(); const next = await nativeReader.read();
        if (next.done) { target.close(); closed.resolve(ok(undefined)); } else target.enqueue(next.value);
      } catch (error) { target.error(error); closed.resolve(err("HTTP read failed")); } },
      async cancel() { try { nativeReader ??= (await response).body.getReader(); await nativeReader.cancel(); closed.resolve(cancelled()); }
        catch { closed.resolve(err("HTTP cleanup failed")); } finally { controller.abort(); } },
    }, { highWaterMark: 0 });
    return { closed: closed.promise, response: () => response.then((value) => ok({ status: value.status, statusText: value.statusText,
      url: value.url, headers: [...value.headers] })), toReadableStream: () => ok(body) };
  }
  const bad = httpMember("/bad"), good = httpMember("/good");
  const admitted = methods.firstAcceptableFetchResponse([bad, good]); assert.equal(admitted.outcome, "ok");
  const result = await admitted.value.result; assert.equal(result.outcome, "ok"); assert.equal(result.value.index, 1);
  assert.equal(await new Response(result.value.body).text(), "chosen payload"); await disconnected.promise;
  assert.equal((await bad.closed).outcome, "cancelled"); assert.equal((await good.closed).outcome, "ok");
});

test("external signal cancels selection with every header parked and waits for cleanup", async (t) => {
  const signal = new AbortController(), gate = deferred(); const a = member(t),
    b = member(t, { cleanup: gate.promise, release: gate.resolve });
  const group = select([a, b], 1, { signal: signal.signal }); signal.abort("uninspected reason");
  await pending(group.result); assert.equal(a.count.cancels, 1); assert.equal(b.count.cancels, 1);
  gate.resolve(); const result = await group.result; assert.equal(result.outcome, "cancelled");
  assert.equal(result.cancellation.kind, "fetch_selection_signal");
});
test("pre-aborted signal drains acquired inputs without invoking response or predicate", async (t) => {
  const signal = new AbortController(); signal.abort(); const a = member(t), b = member(t); let predicates = 0;
  const group = select([a, b], 1, { signal: signal.signal, accept() { predicates += 1; return true; } });
  assert.equal((await group.result).outcome, "cancelled"); assert.equal(predicates, 0);
  assert.equal(a.count.responses, 0); assert.equal(b.count.responses, 0); assert.equal(a.count.cancels, 1); assert.equal(b.count.cancels, 1);
});
test("signal cancellation during loser drain also retires proposed winners", async (t) => {
  const signal = new AbortController(), gate = deferred(); const a = member(t),
    b = member(t, { cleanup: gate.promise, release: gate.resolve }); a.respond();
  const group = select([a, b], 1, { signal: signal.signal }); await pending(group.result); signal.abort();
  await pending(group.result); assert.equal(a.count.cancels, 1); gate.resolve(); assert.equal((await group.result).outcome, "cancelled");
});
test("earlier stopImmediatePropagation listener cannot hide signal cancellation", async (t) => {
  const signal = new AbortController(); signal.signal.addEventListener("abort", (event) => event.stopImmediatePropagation());
  const a = member(t); const group = select([a], 1, { signal: signal.signal }); signal.abort();
  assert.equal((await group.result).outcome, "cancelled"); assert.equal(a.count.cancels, 1);
});
test("group cancellation never aborts the caller-owned signal", async (t) => {
  const signal = new AbortController(); const a = member(t); const group = select([a], 1, { signal: signal.signal });
  await group.cancel(); assert.equal(signal.signal.aborted, false);
});
test("signal aborted after success cannot reclaim transferred bodies", async (t) => {
  const signal = new AbortController(); const a = member(t); a.respond(); const group = select([a], 1, { signal: signal.signal });
  assert.equal((await group.result).outcome, "ok"); signal.abort(); await turn(); assert.equal(a.count.cancels, 0);
});
test("abort listener is removed at successful settlement", async (t) => {
  let dependent;
  const tracked = await api({ AbortSignal: { prototype: AbortSignal.prototype,
    any(signals) { dependent = AbortSignal.any(signals); return dependent; } } });
  const signal = new AbortController(); const a = member(t); const admitted = tracked.quorumFetchResponses([a.handle], 1, { signal: signal.signal });
  assert.equal(admitted.outcome, "ok"); assert.equal(getEventListeners(dependent, "abort").length, 1);
  a.respond(); assert.equal((await admitted.value.result).outcome, "ok"); assert.equal(getEventListeners(dependent, "abort").length, 0);
});
test("missing AbortSignal.any refuses supplied signals before locking inputs", async (t) => {
  const restricted = await api({ AbortSignal: { prototype: AbortSignal.prototype } }); const a = member(t);
  assert.equal(restricted.quorumFetchResponses([a.handle], 1, { signal: new AbortController().signal }).outcome, "err");
  assert.equal(a.count.conversions, 0); assert.equal(a.count.cancels, 0);
  const withoutSignal = restricted.quorumFetchResponses([a.handle], 1); assert.equal(withoutSignal.outcome, "ok");
  await withoutSignal.value.cancel();
});
test("fake signals are refused without reading presentation getters", async (t) => {
  const a = member(t); let touched = 0;
  const fake = { get aborted() { touched += 1; return false; }, get reason() { touched += 1; return "secret"; } };
  assert.equal(methods.quorumFetchResponses([a.handle], 1, { signal: fake }).outcome, "err");
  assert.equal(touched, 0); assert.equal(a.count.conversions, 0);
});
test("overridden signal accessors are refused before native composition or body acquisition", async (t) => {
  const signal = new AbortController(); let touched = 0;
  Object.defineProperties(signal.signal, { aborted: { get() { touched += 1; throw new Error("aborted override"); } },
    reason: { get() { touched += 1; throw new Error("reason override"); } } });
  const a = member(t); const admitted = methods.quorumFetchResponses([a.handle], 1, { signal: signal.signal });
  assert.equal(admitted.outcome, "err"); assert.equal(touched, 0); assert.equal(a.count.conversions, 0);
});
test("overridden listener methods and arbitrary abort reason are not invoked", async (t) => {
  const signal = new AbortController(); let touched = 0;
  signal.signal.addEventListener = () => { touched += 1; throw new Error("listener override"); };
  const a = member(t); const group = select([a], 1, { signal: signal.signal });
  signal.abort({ toString() { touched += 1; throw new Error("reason formatting"); } });
  assert.equal((await group.result).outcome, "cancelled"); assert.equal(touched, 0);
});
test("a host-compatible proxied native signal still propagates cancellation on Node", async (t) => {
  const controller = new AbortController(); const signal = new Proxy(controller.signal, {});
  const a = member(t); const admitted = methods.quorumFetchResponses([a.handle], 1, { signal });
  assert.equal(admitted.outcome, "ok"); controller.abort(); assert.equal((await admitted.value.result).outcome, "cancelled");
});
test("signal abort inside predicate cannot publish a selected response", async (t) => {
  const signal = new AbortController(); const a = member(t); a.respond();
  const group = select([a], 1, { signal: signal.signal, accept() { signal.abort(); return true; } });
  assert.equal((await group.result).outcome, "cancelled"); assert.equal(a.count.cancels, 1);
});
test("signal cancellation preserves cleanup panic precedence", async (t) => {
  const signal = new AbortController(); const a = member(t, { terminal: { outcome: "panicked", message: "drain panic" } });
  const group = select([a], 1, { signal: signal.signal }); signal.abort();
  assert.equal((await group.result).outcome, "panicked");
});
test("an aborted signal does not cancel caller work when setup is refused", async (t) => {
  const signal = new AbortController(); signal.abort(); const a = member(t), b = member(t); const locked = b.stream.getReader();
  const admitted = methods.quorumFetchResponses([a.handle, b.handle], 1, { signal: signal.signal });
  assert.equal(admitted.outcome, "err"); assert.equal(a.count.cancels, 0); assert.equal(a.stream.locked, false); locked.releaseLock();
});
test("null signal is equivalent to omission", async (t) => {
  const a = member(t); a.respond(); assert.equal((await select([a], 1, { signal: null }).result).outcome, "ok");
});
