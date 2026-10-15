/** Actual SSE/JSON-lines and record-owner sources, native Streams; explicit
 * fetch-handle/terminal and request-limit doubles. No task-ABI/WASM claim.
 * node --experimental-vm-modules --test scripts/test_browser_fetch_record_lifecycle.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";
const sources = Object.fromEntries(["fetch-events", "fetch-records"].map(name => [name, readFileSync(
  name === "fetch-records" && process.env.ASUPERSYNC_FETCH_RECORDS_SOURCE
    ? process.env.ASUPERSYNC_FETCH_RECORDS_SOURCE : new URL(`../packages/browser/src/${name}.ts`, import.meta.url), "utf8")]));
console.log(JSON.stringify({ scenario_id: "fetch-record-lifecycle", source_sha256: Object.fromEntries(Object.entries(sources).map(([name, text]) => [name, createHash("sha256").update(text).digest("hex")])),
  evidence_scope: "actual record owner and SSE/JSON-lines parsers; native Streams; explicit fetch and limit doubles" }));
const context = createContext({ ReadableStream, ReadableStreamDefaultReader, TextDecoder, Uint8Array, ArrayBuffer });
const modules = Object.fromEntries(Object.entries(sources).map(([name, text]) => [name, new SourceTextModule(stripTypeScriptTypes(text, { mode: "transform" }), { context })]));
const limits = new SyntheticModule(["BROWSER_FETCH_LIMITS"], function () { this.setExport("BROWSER_FETCH_LIMITS", { maxChunkBytes: 1_048_576 }); }, { context });
await modules["fetch-events"].link(name => name === "./fetch.js" ? limits : modules[name.replace(/^\.\//, "").replace(/\.js$/, "")]);
await modules["fetch-events"].evaluate();
const api = modules["fetch-events"].namespace;
const ok = value => ({ outcome: "ok", value });
const err = (message = "provider error") => ({ outcome: "err", failure: { code: "internal_failure", recoverability: "permanent", message } });
const cancelled = (message = "owner stopped") => ({ outcome: "cancelled", cancellation: { kind: "test", phase: "completed",
  origin_region: "test", origin_task: null, timestamp_nanos: 0, message, truncated: false } });
const panicked = (message = "provider panic") => ({ outcome: "panicked", message });
const message = value => value.outcome === "err" ? value.failure.message : value.outcome === "cancelled" ? value.cancellation.message : value.message;
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
async function pending(promise) { let done = false; void promise.then(() => { done = true; }, () => { done = true; }); await turn(); assert.equal(done, false); }
function fixture(t, format, options = {}) {
  const terminal = deferred(), cleanup = deferred(), started = deferred();
  let cancels = 0, pulls = 0, closedGets = 0;
  const stream = new ReadableStream({
    pull(controller) { pulls++; if (options.bytes !== undefined) {
      if (pulls === 1) controller.enqueue(new TextEncoder().encode(options.bytes));
      else { controller.close(); terminal.resolve(options.terminal ?? ok(undefined)); }
    } },
    async cancel() { cancels++; options.onCancel?.(); started.resolve(); await cleanup.promise;
      if (options.rejectTerminal) terminal.reject({ toString() { assert.fail("do not render provider rejections"); } });
      else terminal.resolve(options.terminal ?? cancelled("normal retirement"));
      if (options.refuse) throw new Error("cancel refused");
    },
  }, { highWaterMark: 0 });
  const head = { status: 200, statusText: "OK", url: "https://example.test/", headers: [["content-type", format === "sse" ? "text/event-stream" : "application/x-ndjson"]] };
  const fetch = { get closed() { closedGets++; return terminal.promise; }, response: () => Promise.resolve(options.response ?? ok(head)),
    toReadableStream: () => ok(stream) };
  const admitted = (format === "sse" ? api.serverSentEvents : api.jsonLines)(fetch);
  assert.equal(admitted.outcome, "ok"); const owner = admitted.value;
  t.after(async () => { cleanup.resolve(); terminal.resolve(cancelled("fixture teardown")); await owner.cancel(); });
  return { owner, stream, terminal, cleanup, started, get cancels() { return cancels; }, get pulls() { return pulls; }, get closedGets() { return closedGets; } };
}
for (const format of ["sse", "json"]) {
  for (const origin of [err, cancelled, panicked]) for (const cleanup of [err, panicked]) {
    test(`${format}: ${origin.name} response plus ${cleanup.name} terminal preserves severity`, { timeout: 2000 }, async t => {
      const f = fixture(t, format, { response: origin("origin"), terminal: cleanup("cleanup") });
      await f.started.promise; await pending(f.owner.closed); assert.equal(f.cancels, 1); f.cleanup.resolve();
      const result = await f.owner.closed;
      const keep = cleanup === err && origin !== err;
      assert.equal(result.outcome, (keep ? origin : cleanup)().outcome); assert.equal(message(result), keep ? "origin" : "cleanup");
      assert.equal(Object.isFrozen(result), true); assert.equal(f.stream.locked, false);
    });
  }
  for (const origin of [cancelled, panicked]) test(`${format}: rejected terminal cannot weaken ${origin.name}`, { timeout: 2000 }, async t => {
    const f = fixture(t, format, { response: origin("origin"), rejectTerminal: true });
    await f.started.promise; f.cleanup.resolve(); const result = await f.owner.closed;
    assert.equal(result.outcome, origin().outcome); assert.equal(message(result), "origin");
  });
  test(`${format}: cancellation callbacks cannot mutate a retained response failure`, { timeout: 2000 }, async t => {
    const envelope = panicked("original");
    const f = fixture(t, format, { response: envelope, onCancel() { envelope.message = "changed"; } });
    await f.started.promise; f.cleanup.resolve(); const result = await f.owner.closed;
    assert.equal(result.message, "original"); assert.equal(Object.isFrozen(result), true);
  });
  test(`${format}: idle terminal failure is observed without a body read and still drains`, { timeout: 2000 }, async t => {
    const f = fixture(t, format); await turn(); assert.equal(f.pulls, 0);
    f.terminal.resolve(err("idle terminal")); await turn(); assert.equal(f.cancels, 1);
    await pending(f.owner.closed); f.cleanup.resolve(); const result = await f.owner.closed;
    assert.equal(result.outcome, "err"); assert.equal(message(result), "idle terminal"); assert.equal(f.stream.locked, false);
    assert.equal(f.closedGets, 1, "one source receipt is shared by all paths");
  });
  test(`${format}: malformed idle terminal fails closed rather than leaking its envelope`, { timeout: 2000 }, async t => {
    const f = fixture(t, format); f.terminal.resolve({ outcome: "panicked", message: 42 });
    await turn(); assert.equal(f.cancels, 1); f.cleanup.resolve(); const result = await f.owner.closed;
    assert.equal(result.outcome, "err"); assert.match(result.failure.message, /invalid fetch record outcome/);
  });
  test(`${format}: successful terminal is not parser EOF and never discards unread bytes`, { timeout: 2000 }, async t => {
    const f = fixture(t, format, { bytes: format === "sse" ? "data: one\n\ndata: two\n\n" : "1\n2\n" });
    f.terminal.resolve(ok(undefined)); await pending(f.owner.closed); assert.equal(f.pulls, 0);
    const values = []; for await (const item of f.owner.readable) values.push(format === "sse" ? item.data : item.value);
    assert.deepEqual(values, format === "sse" ? ["one", "two"] : [1, 2]);
    assert.equal((await f.owner.closed).outcome, "ok"); assert.equal(f.cancels, 0); assert.equal(f.closedGets, 1);
  });
}
test("a JSON parse error stays a decode failure through its own expected retirement cancellation", { timeout: 2000 }, async t => {
  const f = fixture(t, "json", { bytes: "not-json\n" }), reader = f.owner.readable.getReader(); void reader.closed.catch(() => {});
  const read = reader.read(); void read.catch(() => {}); await f.started.promise; await pending(read); f.cleanup.resolve();
  await assert.rejects(read, error => error.cause.outcome === "err" && error.cause.failure.code === "decode_failure");
  assert.equal((await f.owner.closed).outcome, "err");
});
test("malformed conversion receipts refuse before locking a body", () => {
  for (const body of [{ outcome: "err", failure: {} }, { outcome: "other" }, null]) {
    const fetch = { response: () => Promise.resolve(ok(undefined)), closed: Promise.resolve(ok(undefined)), toReadableStream: () => body };
    const result = api.jsonLines(fetch); assert.equal(result.outcome, "err"); assert.equal(Object.isFrozen(result), true);
    assert.match(result.failure.message, /invalid fetch record outcome/);
  }
});
test("throwing receipt getters do not expose arbitrary exception hooks", { timeout: 2000 }, async t => {
  let invoked = 0;
  const f = fixture(t, "json", { terminal: { get outcome() { throw { toString() { invoked++; return "private"; }, get cause() { invoked++; } }; } } });
  const cancellation = f.owner.cancel(); await f.started.promise; f.cleanup.resolve();
  const result = await cancellation; assert.equal(result.outcome, "err"); assert.equal(invoked, 0);
});
test("receipt discriminant and panic message are each snapshotted exactly once", { timeout: 2000 }, async t => {
  let tags = 0, messages = 0;
  const envelope = { get outcome() { return ++tags === 1 ? "panicked" : "ok"; },
    get message() { return ++messages === 1 ? "original panic" : 42; } };
  const f = fixture(t, "json", { response: envelope });
  await f.started.promise; f.cleanup.resolve(); const result = await f.owner.closed;
  assert.equal(result.outcome, "panicked"); assert.equal(result.message, "original panic");
  assert.equal(tags, 1); assert.equal(messages, 1);
});
