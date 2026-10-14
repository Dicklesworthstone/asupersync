/** Cross-combinator lifecycle regressions against the actual TypeScript source.
 * Native Streams are real; fetch handles/terminal receipts and the imported
 * request limit are explicit doubles. This is not SDK task-ABI or WASM proof.
 * Run: node --experimental-vm-modules --test scripts/test_browser_fetch_group_lifecycle.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { getEventListeners } from "node:events";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";

const source = readFileSync(process.env.ASUPERSYNC_FETCH_COMBINATORS_SOURCE
  ?? new URL("../packages/browser/src/fetch-combinators.ts", import.meta.url), "utf8");
console.log(JSON.stringify({ scenario_id: "browser-fetch-group-lifecycle",
  source_sha256: createHash("sha256").update(source).digest("hex"),
  evidence_scope: "actual combinators; native Streams; explicit handles, receipts and request-limit double" }));
async function api(globals = {}) {
  const context = createContext({ ReadableStream, ReadableStreamDefaultReader, AbortSignal, EventTarget, ...globals });
  const limits = new SyntheticModule(["BROWSER_FETCH_LIMITS"], function () {
    this.setExport("BROWSER_FETCH_LIMITS", Object.freeze({ maxRequestsPerRuntime: 64 }));
  }, { context });
  const module = new SourceTextModule(stripTypeScriptTypes(source, { mode: "transform" }), { context });
  await module.link((name) => { assert.equal(name, "./fetch.js"); return limits; });
  await module.evaluate();
  return module.namespace;
}
const methods = await api();
const ok = (value) => ({ outcome: "ok", value });
const cancelled = (message) => ({ outcome: "cancelled", cancellation: { kind: "test_cancel", phase: "completed",
  origin_region: "explicit-test-owner", origin_task: null, timestamp_nanos: 0, message, truncated: false } });
const failure = (kind, message) => kind === "panicked" ? { outcome: kind, message }
  : kind === "cancelled" ? cancelled(message)
    : { outcome: "err", failure: { code: "internal_failure", recoverability: "unknown", message } };
const message = (outcome) => outcome.message ?? outcome.cancellation?.message ?? outcome.failure?.message;
const deferred = () => { let resolve; const promise = new Promise((done) => { resolve = done; }); return { promise, resolve }; };
const turn = () => new Promise((resolve) => setImmediate(resolve));
async function pending(promise) {
  let settled = false;
  void promise.then(() => { settled = true; }, () => { settled = true; });
  await turn();
  assert.equal(settled, false, "result must retain the cleanup barrier");
}
function member(t, options = {}) {
  const headers = deferred(), completion = deferred();
  const count = { pulls: 0, cancels: 0, responses: 0, conversions: 0 };
  const body = new ReadableStream({
    pull() { count.pulls += 1; },
    async cancel() {
      count.cancels += 1;
      await options.gate?.promise;
      completion.resolve(options.terminal ?? cancelled("expected loser cancellation"));
      if (options.refuse) throw new Error("explicit cancellation refusal");
    },
  }, { highWaterMark: 0 });
  const handle = { closed: completion.promise,
    response() { count.responses += 1; return headers.promise; },
    toReadableStream() { count.conversions += 1; return ok(body); },
  };
  t.after(async () => {
    options.gate?.resolve();
    if (!body.locked) { try { await body.cancel(); } catch { /* Intentional refusal. */ } }
  });
  return { handle, body, count, completion,
    respond(outcome = ok({ status: 200, statusText: "OK", url: "https://example.test/", headers: [] })) {
      headers.resolve(outcome);
    },
  };
}
function group(kind, list, options, implementation = methods) {
  const admitted = implementation[kind](list.map((item) => item.handle), options);
  assert.equal(admitted.outcome, "ok");
  return admitted.value;
}
const rank = { err: 1, cancelled: 2, panicked: 3 };
const kinds = ["raceFetchResponses", "joinFetchResponses"];
for (const kind of kinds) {
  for (const initial of Object.keys(rank)) for (const cleanup of Object.keys(rank)) {
    test(`${kind}: ${initial} followed by ${cleanup} cleanup preserves the strongest outcome`, { timeout: 3000 }, async (t) => {
      const gate = deferred();
      const a = member(t), b = member(t, { gate, terminal: failure(cleanup, "cleanup"), refuse: cleanup === "cancelled" });
      const run = group(kind, [a, b]);
      a.respond(failure(initial, "initial"));
      await pending(run.result);
      assert.equal(b.count.cancels, 1);
      gate.resolve();
      const result = await run.result;
      const expected = rank[cleanup] >= rank[initial] ? cleanup : initial;
      assert.equal(result.outcome, expected);
      assert.equal(message(result), rank[cleanup] >= rank[initial] ? "cleanup" : "initial");
      assert.equal(Object.isFrozen(result), true);
      for (const item of [a, b]) {
        assert.equal(item.count.cancels, 1);
        assert.equal(item.count.pulls, 0);
        assert.equal(item.body.locked, false);
      }
    });
  }
  test(`${kind}: caller cancellation upgrades an error during drain`, { timeout: 3000 }, async (t) => {
    const gate = deferred();
    const a = member(t), b = member(t, { gate });
    const run = group(kind, [a, b]);
    a.respond(failure("err", "initial error"));
    await pending(run.result);
    const first = run.cancel("owner shutdown"), second = run.cancel("later reason");
    assert.equal(first, second);
    await pending(first);
    gate.resolve();
    const result = await run.result;
    assert.equal(result.outcome, "cancelled");
    assert.equal(message(result), "owner shutdown");
    assert.equal(await first, result);
  });
  test(`${kind}: expected loser cancellation does not upgrade an error`, { timeout: 3000 }, async (t) => {
    const a = member(t), b = member(t);
    const run = group(kind, [a, b]); a.respond(failure("err", "network"));
    const result = await run.result;
    assert.equal(result.outcome, "err"); assert.equal(message(result), "network");
  });
  test(`${kind}: cleanup panic overrides explicit caller cancellation`, { timeout: 3000 }, async (t) => {
    const gate = deferred();
    const a = member(t, { gate, terminal: failure("panicked", "cleanup panic") }), b = member(t);
    const run = group(kind, [a, b]); const stopped = run.cancel("owner shutdown");
    await pending(stopped); gate.resolve();
    const result = await stopped;
    assert.equal(result.outcome, "panicked"); assert.equal(message(result), "cleanup panic");
  });
  for (const severity of Object.keys(rank)) {
    test(`${kind}: ${severity} cleanup ties use input order, not completion order`, { timeout: 3000 }, async (t) => {
      const gate = deferred();
      const a = member(t, { gate, terminal: failure(severity, "first input"), refuse: severity === "cancelled" });
      const b = member(t, { terminal: failure(severity, "second input"), refuse: severity === "cancelled" });
      const run = group(kind, [a, b]); a.respond(failure("err", "initial"));
      await pending(run.result); gate.resolve();
      const result = await run.result;
      assert.equal(result.outcome, severity); assert.equal(message(result), "first input");
    });
  }
  test(`${kind}: successful ownership transfer leaves unread bodies and later cancel is inert`, { timeout: 3000 }, async (t) => {
    const a = member(t), b = member(t);
    a.respond(); b.respond();
    const run = group(kind, [a, b]); const result = await run.result;
    assert.equal(result.outcome, "ok");
    const winners = kind === "raceFetchResponses" ? [result.value] : result.value;
    assert.equal(winners.length, kind === "raceFetchResponses" ? 1 : 2);
    for (const winner of winners) {
      const item = [a, b][winner.index];
      assert.equal(item.body, winner.body); assert.equal(item.body.locked, false);
      assert.equal(item.count.pulls, 0); assert.equal(item.count.cancels, 0);
    }
    assert.equal((await run.cancel()).outcome, "ok");
    for (const winner of winners) assert.equal([a, b][winner.index].count.cancels, 0);
  });
}

for (const kind of kinds) {
  test(`${kind}: pre-aborted signal drains inputs without invoking response methods`, { timeout: 3000 }, async (t) => {
    const controller = new AbortController(); controller.abort();
    const gate = deferred(), a = member(t, { gate }), b = member(t);
    const run = group(kind, [a, b], { signal: controller.signal });
    assert.equal(a.count.responses, 0); assert.equal(b.count.responses, 0);
    assert.equal(a.count.cancels, 1); assert.equal(b.count.cancels, 1);
    await pending(run.result); gate.resolve();
    const result = await run.result;
    assert.equal(result.outcome, "cancelled");
    assert.equal(result.cancellation.kind, kind === "raceFetchResponses" ? "fetch_race_signal" : "fetch_join_signal");
    assert.equal(a.body.locked, false); assert.equal(b.body.locked, false);
  });
  test(`${kind}: signal during drain retires ready bodies and waits for every cleanup`, { timeout: 3000 }, async (t) => {
    const controller = new AbortController(), gate = deferred();
    const a = member(t), b = member(t, { gate }); a.respond();
    const run = group(kind, [a, b], { signal: controller.signal });
    await pending(run.result); controller.abort();
    assert.equal(a.count.cancels, 1); assert.equal(b.count.cancels, 1);
    await pending(run.result);
    const cancelledAgain = run.cancel("late manual cancellation");
    gate.resolve();
    const result = await run.result;
    assert.equal(result.outcome, "cancelled"); assert.match(result.cancellation.kind, /_signal$/);
    assert.equal(await cancelledAgain, result);
    for (const item of [a, b]) { assert.equal(item.count.pulls, 0); assert.equal(item.body.locked, false); }
  });
  test(`${kind}: earlier stopImmediatePropagation cannot suppress group cancellation`, { timeout: 3000 }, async (t) => {
    const controller = new AbortController();
    controller.signal.addEventListener("abort", (event) => event.stopImmediatePropagation());
    const a = member(t), b = member(t);
    const run = group(kind, [a, b], { signal: controller.signal });
    controller.abort();
    assert.equal(a.count.cancels, 1); assert.equal(b.count.cancels, 1);
    assert.equal((await run.result).outcome, "cancelled");
  });
  test(`${kind}: cancellation during body conversion is observed before response methods`, { timeout: 3000 }, async (t) => {
    const controller = new AbortController(), a = member(t), b = member(t);
    const convert = a.handle.toReadableStream;
    a.handle.toReadableStream = () => { controller.abort(); return convert(); };
    const run = group(kind, [a, b], { signal: controller.signal });
    assert.equal(a.count.responses, 0); assert.equal(b.count.responses, 0);
    assert.equal(a.count.cancels, 1); assert.equal(b.count.cancels, 1);
    assert.equal((await run.result).outcome, "cancelled");
  });
  test(`${kind}: arbitrary abort reasons are neither read nor stringified`, { timeout: 3000 }, async (t) => {
    const controller = new AbortController(), a = member(t);
    const run = group(kind, [a], { signal: controller.signal });
    let inspected = 0;
    const reason = { get cause() { inspected += 1; throw new Error("cause inspected"); },
      toString() { inspected += 1; throw new Error("stringified"); },
      [Symbol.toPrimitive]() { inspected += 1; throw new Error("coerced"); } };
    controller.abort(reason);
    assert.equal(a.count.cancels, 1);
    assert.equal((await run.result).outcome, "cancelled"); assert.equal(inspected, 0);
  });
  test(`${kind}: caller shutdown dominates ordinary cleanup failure but not panic`, { timeout: 3000 }, async (t) => {
    for (const terminalKind of ["err", "panicked"]) {
      const controller = new AbortController(), gate = deferred();
      const a = member(t, { gate, terminal: failure(terminalKind, "cleanup") });
      const run = group(kind, [a], { signal: controller.signal });
      controller.abort(); assert.equal(a.count.cancels, 1);
      await pending(run.result); gate.resolve();
      assert.equal((await run.result).outcome, terminalKind === "panicked" ? "panicked" : "cancelled");
    }
  });
  test(`${kind}: manual group cancellation never aborts the borrowed signal`, { timeout: 3000 }, async (t) => {
    const controller = new AbortController(), a = member(t);
    const run = group(kind, [a], { signal: controller.signal });
    assert.equal((await run.cancel()).outcome, "cancelled");
    assert.equal(controller.signal.aborted, false);
    assert.equal(getEventListeners(controller.signal, "abort").length, 0);
  });
  test(`${kind}: abort after transfer cannot reclaim the delivered body`, { timeout: 3000 }, async (t) => {
    const controller = new AbortController(), a = member(t); a.respond();
    const run = group(kind, [a], { signal: controller.signal });
    assert.equal((await run.result).outcome, "ok");
    controller.abort(); await turn();
    assert.equal(a.count.cancels, 0); assert.equal(a.count.pulls, 0); assert.equal(a.body.locked, false);
  });
  test(`${kind}: invalid or customized signals refuse before ownership transfer`, { timeout: 3000 }, async (t) => {
    const a = member(t), controller = new AbortController(); let reads = 0;
    Object.defineProperty(controller.signal, "aborted", { get() { reads += 1; throw new Error("getter invoked"); } });
    for (const options of [null, { signal: {} }, { signal: controller.signal }]) {
      assert.equal(methods[kind]([a.handle], options).outcome, "err");
    }
    assert.equal(reads, 0); assert.equal(a.count.conversions, 0); assert.equal(a.count.cancels, 0);
  });
  test(`${kind}: hosts without signal support still run unsignalled groups`, { timeout: 3000 }, async (t) => {
    const implementation = await api({ AbortSignal: undefined }), a = member(t); a.respond();
    assert.equal(implementation[kind]([a.handle], { signal: new AbortController().signal }).outcome, "err");
    assert.equal(a.count.conversions, 0);
    assert.equal((await group(kind, [a], undefined, implementation).result).outcome, "ok");
  });
  test(`${kind}: private signal listeners are removed on success, error and cancellation`, { timeout: 3000 }, async (t) => {
    const copies = [];
    // Observe the private dependency while still using native any() and getters.
    function ObservedSignal() { throw new Error("signal construction is forbidden"); }
    ObservedSignal.prototype = AbortSignal.prototype;
    ObservedSignal.any = (signals) => { const copy = AbortSignal.any(signals); copies.push(copy); return copy; };
    const implementation = await api({ AbortSignal: ObservedSignal });
    for (const end of ["ok", "err", "cancelled"]) {
      const controller = new AbortController(), a = member(t);
      const run = group(kind, [a], { signal: controller.signal }, implementation);
      const copy = copies.at(-1);
      assert.ok(copy); assert.equal(getEventListeners(copy, "abort").length, 1);
      if (end === "cancelled") controller.abort();
      else a.respond(end === "ok" ? undefined : failure("err", "network"));
      assert.equal((await run.result).outcome, end);
      assert.equal(getEventListeners(copy, "abort").length, 0);
    }
  });
  test(`${kind}: refused setup rolls back locks even when conversion aborts the signal`, { timeout: 3000 }, async (t) => {
    const controller = new AbortController(), a = member(t), b = member(t);
    const held = b.body.getReader(); t.after(() => held.releaseLock());
    const convert = a.handle.toReadableStream;
    a.handle.toReadableStream = () => { controller.abort(); return convert(); };
    assert.equal(methods[kind]([a.handle, b.handle], { signal: controller.signal }).outcome, "err");
    assert.equal(a.body.locked, false); assert.equal(a.count.cancels, 0); assert.equal(b.count.cancels, 0);
  });
}
test("empty join retains its identity with a valid pre-aborted signal", async () => {
  const controller = new AbortController(); controller.abort();
  const admitted = methods.joinFetchResponses([], { signal: controller.signal });
  assert.equal(admitted.outcome, "ok");
  const result = await admitted.value.result;
  assert.equal(result.outcome, "ok"); assert.equal(result.value.length, 0);
});

for (const kind of kinds) {
  test(`${kind}: group signal aborts real loopback requests and joins native cleanup`, { timeout: 5000 }, async (t) => {
    const received = deferred(), disconnected = deferred(), controllers = [];
    let requests = 0, closes = 0;
    const server = createServer((_request, response) => {
      requests += 1; if (requests === 2) received.resolve();
      // Deliberately leave headers parked until the client aborts the request.
      response.on("close", () => { closes += 1; if (closes === 2) disconnected.resolve(); });
    });
    await new Promise((resolve, reject) => {
      server.once("error", reject); server.listen(0, "127.0.0.1", resolve);
    });
    t.after(async () => {
      for (const controller of controllers) controller.abort();
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    });
    const origin = `http://127.0.0.1:${server.address().port}`;
    function nativeMember(index) {
      const controller = new AbortController(), completion = deferred(); controllers.push(controller);
      let response;
      const count = { cancels: 0 };
      // Only the member controller reaches fetch; the group signal cannot bypass
      // the combinator's owned-reader cancellation path.
      const headers = fetch(`${origin}/${index}`, { signal: controller.signal }).then((value) => {
        response = value;
        return ok({ status: value.status, statusText: value.statusText, url: value.url, headers: [...value.headers] });
      }, () => cancelled("native fetch aborted"));
      const body = new ReadableStream({ async cancel() {
        count.cancels += 1; controller.abort(); await headers;
        if (response?.body) { try { await response.body.cancel(); } catch { /* Native abort. */ } }
        completion.resolve(cancelled("native cleanup complete"));
      } }, { highWaterMark: 0 });
      return { body, count, handle: { response: () => headers, closed: completion.promise, toReadableStream: () => ok(body) } };
    }
    const members = [nativeMember(0), nativeMember(1)], controller = new AbortController();
    const run = group(kind, members, { signal: controller.signal });
    await received.promise; await pending(run.result); controller.abort();
    for (const item of members) assert.equal(item.count.cancels, 1);
    assert.equal((await run.result).outcome, "cancelled");
    await disconnected.promise;
    assert.equal(requests, 2); assert.equal(closes, 2);
    for (const item of members) {
      assert.equal(item.body.locked, false); assert.equal((await item.handle.closed).outcome, "cancelled");
    }
  });
}
