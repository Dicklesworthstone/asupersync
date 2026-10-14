/** Selection failure ordering against actual TypeScript and native Streams.
 * Fetch handles and terminal receipts are explicit doubles, not SDK/WASM proof.
 * node --experimental-vm-modules --test scripts/test_browser_fetch_selection_outcomes.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { createContext, SourceTextModule } from "node:vm";

const source = readFileSync(process.env.ASUPERSYNC_FETCH_SELECTION_SOURCE
  ?? new URL("../packages/browser/src/fetch-selection.ts", import.meta.url), "utf8");
console.log(JSON.stringify({ scenario_id: "fetch-selection-outcome-order", source_sha256: createHash("sha256").update(source).digest("hex"),
  evidence_scope: "actual selection TypeScript; native Streams/signals; explicit handle and terminal doubles" }));
const module = new SourceTextModule(stripTypeScriptTypes(source, { mode: "transform" }), {
  context: createContext({ ReadableStream, ReadableStreamDefaultReader, AbortSignal, EventTarget }),
});
await module.link(() => { throw new Error("unexpected runtime import"); });
await module.evaluate();
const api = module.namespace;
const ok = value => ({ outcome: "ok", value });
const err = message => ({ outcome: "err", failure: { code: "internal_failure", recoverability: "unknown", message } });
const cancelled = message => ({ outcome: "cancelled", cancellation: { kind: "test", phase: "completed",
  origin_region: "test-owner", origin_task: null, timestamp_nanos: 0, message, truncated: false } });
const panicked = message => ({ outcome: "panicked", message });
const head = { status: 200, statusText: "OK", url: "https://example.test/", headers: [] };
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
async function pending(promise) { let done = false; void promise.then(() => { done = true; }); await turn(); assert.equal(done, false); }
const message = outcome => outcome.outcome === "err" ? outcome.failure.message
  : outcome.outcome === "cancelled" ? outcome.cancellation.message : outcome.message;

function member(t, options = {}) {
  const headers = deferred(), closed = deferred(), release = deferred(), started = deferred();
  let cancelledOnce = false, pulls = 0;
  const stream = new ReadableStream({
    pull() { pulls++; },
    async cancel() {
      cancelledOnce = true;
      started.resolve();
      if (options.held) await release.promise;
      closed.resolve(options.terminal ?? cancelled("normal retirement"));
      if (options.refuse) throw new Error("refused cancellation");
    },
  }, { highWaterMark: 0 });
  const handle = { closed: closed.promise, response: () => headers.promise, toReadableStream: () => ok(stream) };
  t.after(async () => { release.resolve(); if (!stream.locked) { try { await stream.cancel(); } catch {} } });
  return { handle, stream, started: started.promise, release: release.resolve, respond: headers.resolve,
    get cancelled() { return cancelledOnce; }, get pulls() { return pulls; } };
}
function select(list, first, options) {
  const handles = list.map(value => value.handle);
  const admitted = first ? api.firstAcceptableFetchResponse(handles, options) : api.quorumFetchResponses(handles, 1, options);
  assert.equal(admitted.outcome, "ok");
  return admitted.value;
}
const outcomes = [err, cancelled, panicked];
for (const first of [false, true]) {
  for (let initial = 0; initial < outcomes.length; initial++) {
    for (let cleanup = 0; cleanup < outcomes.length; cleanup++) {
      test(`${first ? "first" : "quorum"}: ${outcomes[initial].name} followed by ${outcomes[cleanup].name} cleanup`, { timeout: 2000 }, async t => {
        const a = member(t), b = member(t, { held: true, terminal: outcomes[cleanup]("cleanup"), refuse: cleanup === 1 });
        const group = select([a, b], first);
        a.respond(outcomes[initial]("initial"));
        await b.started;
        assert.equal(a.cancelled, true);
        await pending(group.result);
        b.release();
        const result = await group.result;
        assert.equal(result.outcome, outcomes[Math.max(initial, cleanup)]("").outcome);
        assert.equal(message(result), cleanup >= initial ? "cleanup" : "initial");
        assert.equal(a.stream.locked, false); assert.equal(b.stream.locked, false);
        assert.equal(a.pulls + b.pulls, 0);
      });
    }
  }
  for (const viaSignal of [false, true]) {
    test(`${first ? "first" : "quorum"}: late ${viaSignal ? "signal" : "manual"} cancellation strengthens an error while drain is parked`, { timeout: 2000 }, async t => {
      const controller = new AbortController();
      const a = member(t), b = member(t, { held: true });
      const group = select([a, b], first, { signal: controller.signal });
      a.respond(err("initial error")); await b.started; await pending(group.result);
      if (viaSignal) controller.abort(); else void group.cancel("owner stop");
      await pending(group.result); b.release();
      const result = await group.result;
      assert.equal(result.outcome, "cancelled");
      assert.equal(message(result), viaSignal ? "fetch selection aborted by caller signal" : "owner stop");
    });
    test(`${first ? "first" : "quorum"}: ${viaSignal ? "signal" : "manual"} cancellation is not demoted by a cleanup error`, { timeout: 2000 }, async t => {
      const controller = new AbortController();
      const a = member(t), b = member(t, { held: true, terminal: err("cleanup error") });
      const group = select([a, b], first, { signal: controller.signal });
      if (viaSignal) controller.abort(); else void group.cancel("owner stop");
      await b.started; await pending(group.result); b.release();
      assert.equal((await group.result).outcome, "cancelled");
    });
  }
  test(`${first ? "first" : "quorum"}: ordinary retirement of a selected winner is not a new cancellation`, { timeout: 2000 }, async t => {
    const a = member(t), b = member(t, { held: true, terminal: err("real cleanup error") });
    a.respond(ok(head)); const group = select([a, b], first);
    await b.started; assert.equal(a.cancelled, false); await pending(group.result);
    b.release(); const result = await group.result;
    assert.equal(result.outcome, "err"); assert.equal(message(result), "real cleanup error");
    assert.equal(a.cancelled, true); assert.equal(a.stream.locked, false);
  });
  for (const reverse of [false, true]) {
    test(`${first ? "first" : "quorum"}: equal cleanup panics use input order (reverse=${reverse})`, { timeout: 2000 }, async t => {
      const a = member(t), b = member(t, { held: true, terminal: panicked("lower index") }),
        c = member(t, { held: true, terminal: panicked("higher index") });
      a.respond(ok(head)); const group = select([a, b, c], first);
      await Promise.all([b.started, c.started]);
      (reverse ? c : b).release(); await a.started; await pending(group.result);
      (reverse ? b : c).release();
      assert.equal(message(await group.result), "lower index");
    });
  }
  test(`${first ? "first" : "quorum"}: first owner cause survives repeated cancellation and ordinary retirement`, { timeout: 2000 }, async t => {
    const controller = new AbortController(); const a = member(t, { held: true });
    const group = select([a], first, { signal: controller.signal });
    const barrier = group.cancel("first owner cause");
    assert.equal(barrier, group.cancel("second cause")); controller.abort();
    await a.started; await pending(barrier); a.release();
    assert.equal(message(await group.result), "first owner cause");
  });
  test(`${first ? "first" : "quorum"}: clean loser cancellation preserves unread success and post-transfer cancellation is inert`, { timeout: 2000 }, async t => {
    const a = member(t), b = member(t, { held: true }); a.respond(ok(head));
    const group = select([a, b], first); await b.started; await pending(group.result);
    b.release(); const result = await group.result;
    assert.equal(result.outcome, "ok"); assert.equal(a.cancelled, false);
    assert.equal(a.pulls, 0); assert.equal(a.stream.locked, false);
    assert.equal((await group.cancel()).outcome, "ok"); assert.equal(a.cancelled, false);
  });
}
