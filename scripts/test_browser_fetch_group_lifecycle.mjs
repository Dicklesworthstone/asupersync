/** Cross-combinator lifecycle regressions against the actual TypeScript source.
 * Native Streams are real; fetch handles/terminal receipts and the imported
 * request limit are explicit doubles. This is not SDK task-ABI or WASM proof.
 * Run: node --experimental-vm-modules --test scripts/test_browser_fetch_group_lifecycle.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
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
