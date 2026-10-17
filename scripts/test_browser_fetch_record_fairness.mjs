/**
 * Real record-decoder source, native Streams/Promises and host task scheduling.
 * The upstream FetchStreamHandle and its limit export are explicit doubles;
 * this is not evidence for the network manager, task ABI, WASM, or browser UI.
 * Run: node --experimental-vm-modules --test scripts/test_browser_fetch_record_fairness.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";

const names = ["fetch-records", "fetch-events"];
const sources = Object.fromEntries(names.map(name => [name,
  readFileSync(new URL(`../packages/browser/src/${name}.ts`, import.meta.url), "utf8")]));
const code = Object.fromEntries(names.map(name => [name, stripTypeScriptTypes(sources[name], { mode: "transform" })]));
console.log(JSON.stringify({ scenario_id: "fetch-record-host-fairness",
  evidence_scope: "actual decoders, native Streams and host timers, upstream fetch-handle double",
  source_sha256: Object.fromEntries(names.map(name => [name, createHash("sha256").update(sources[name]).digest("hex")])) }));
const ok = value => ({ outcome: "ok", value });
const failure = message => ({ outcome: "err", failure: { code: "decode_failure", recoverability: "permanent", message } });
const cancelled = reason => ({ outcome: "cancelled", cancellation: { kind: "user", phase: "completed",
  origin_region: "test", origin_task: null, timestamp_nanos: 0, message: String(reason), truncated: false } });
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }
const turn = () => new Promise(done => setImmediate(done));
const bytes = text => new TextEncoder().encode(text);

async function decoders(globals = {}) {
  const timers = new Set();
  const state = { scheduled: 0, fired: 0, cleared: 0 };
  const context = createContext({ ReadableStream, ReadableStreamDefaultReader, TextDecoder, Uint8Array,
    setTimeout(callback, delay) {
      state.scheduled += 1;
      const timer = setTimeout(() => { timers.delete(timer); state.fired += 1; callback(); }, delay);
      timers.add(timer);
      return timer;
    },
    clearTimeout(timer) { if (timers.delete(timer)) state.cleared += 1; clearTimeout(timer); },
    ...globals,
  });
  const limits = new SyntheticModule(["BROWSER_FETCH_LIMITS"], function () {
    // Exact maxChunkBytes of the fetch adapter; the parser is the system under test.
    this.setExport("BROWSER_FETCH_LIMITS", Object.freeze({ maxChunkBytes: 1_048_576 }));
  }, { context });
  const modules = Object.fromEntries(names.map(name => [name, new SourceTextModule(code[name], { context, identifier: name })]));
  await modules["fetch-events"].link(name => name === "./fetch.js" ? limits : modules[name.slice(2, -3)]);
  await modules["fetch-events"].evaluate();
  return { ...modules["fetch-events"].namespace, state, timers, context };
}

function upstream(chunks, media, options = {}) {
  const terminal = deferred();
  const state = { pulls: 0, cancels: 0, retires: 0 };
  let controller;
  let index = 0;
  const body = new ReadableStream({
    start(value) { controller = value; },
    pull(controller) {
      state.pulls += 1;
      options.onPull?.(state.pulls);
      if (index === chunks.length) { controller.close(); terminal.resolve(ok(undefined)); return; }
      const value = chunks[index++];
      controller.enqueue(typeof value === "string" ? bytes(value) : value);
    },
    async cancel(reason) {
      state.cancels += 1;
      await options.cancelGate;
      terminal.resolve(cancelled(reason));
    },
  }, { highWaterMark: 0 });
  const fetch = { closed: terminal.promise,
    async response() { return ok({ status: 200, statusText: "OK", url: "https://example.test",
      headers: [["content-type", media]] }); },
    toReadableStream() { return ok(body); },
    async retire() { state.retires += 1; await options.retireGate; return options.retirement ?? ok(undefined); },
  };
  return { fetch, state, fail(message) { terminal.resolve(failure(message)); controller.error(new Error("host failure")); } };
}
function open(t, sdk, source, format = "sse", options) {
  const result = format === "sse" ? sdk.serverSentEvents(source.fetch, options) : sdk.jsonLines(source.fetch, options);
  assert.equal(result.outcome, "ok");
  t.after(() => result.value.cancel("fixture cleanup"));
  return result.value;
}
function manualTasks() {
  const entered = deferred(), pending = new Map();
  let sequence = 0;
  return { entered, pending, globals: {
    setTimeout(callback) { const id = ++sequence; pending.set(id, callback); entered.resolve(); return id; },
    clearTimeout(id) { pending.delete(id); },
  }, run() { for (const [id, callback] of [...pending]) { pending.delete(id); callback(); } } };
}
async function parked(tasks, read) {
  const first = await Promise.race([tasks.entered.promise.then(() => "parked"), read.then(() => "record", () => "error")]);
  assert.equal(first, "parked", "decoder must yield before exhausting this ready input");
  assert.equal(tasks.pending.size, 1, "one owned host task, not a timer backlog");
}

for (const scenario of [
  { name: "coalesced SSE comments", format: "sse", media: "text/event-stream", chunks: [": ignored\n".repeat(4096) + "data: too late\n\n"] },
  { name: "coalesced empty NDJSON lines", format: "json", media: "application/x-ndjson", chunks: ["\n".repeat(4096) + "42\n"] },
  { name: "ready empty byte chunks", format: "sse", media: "text/event-stream", chunks: [...Array.from({ length: 4096 }, () => new Uint8Array()), "data: too late\n\n"] },
  { name: "one long unterminated line fragment", format: "sse", media: "text/event-stream", chunks: [":" + "x".repeat(500_000) + "\ndata: too late\n\n"], options: { maxLineBytes: 600_000 } },
]) {
  test(`host cancellation interrupts ${scenario.name}`, { timeout: 5000 }, async t => {
    const sdk = await decoders();
    let records, stop, parentTimer;
    const source = upstream(scenario.chunks, scenario.media, { onPull(pulls) {
      if (pulls === 1) parentTimer = setTimeout(() => { stop = records.cancel("host deadline"); }, 0);
    } });
    t.after(() => clearTimeout(parentTimer));
    records = open(t, sdk, source, scenario.format, scenario.options);
    await assert.rejects(records.readable.getReader().read(), error => error.cause?.outcome === "cancelled",
      "a ready-input microtask chain must not deliver the final record before host cancellation");
    assert.equal((await stop).outcome, "cancelled");
    assert.equal((await records.closed).outcome, "cancelled");
    assert.equal(source.state.cancels, 1);
    assert.equal(source.state.retires, 1);
    assert.equal(sdk.timers.size, 0);
    assert.ok(sdk.state.scheduled >= 1);
    if (scenario.chunks.length > 1) assert.ok(source.state.pulls < scenario.chunks.length);
  });
}

test("an eager consumer cannot reset the work budget by reading one record at a time", { timeout: 5000 }, async t => {
  const sdk = await decoders();
  let consumed = 0, observed, parentTimer;
  const count = 2048;
  const source = upstream([Array.from({ length: count }, (_, i) => `${i}\n`).join("")], "application/ndjson", {
    onPull(pulls) { if (pulls === 1) parentTimer = setTimeout(() => { observed = consumed; }, 0); },
  });
  t.after(() => clearTimeout(parentTimer));
  const records = open(t, sdk, source, "json");
  for await (const record of records.readable) {
    assert.equal(record.value, consumed);
    assert.equal(record.lineNumber, ++consumed);
  }
  assert.equal(consumed, count);
  assert.ok(observed !== undefined && observed < count, "the host must run before the eager consumer exhausts all records");
  assert.equal((await records.closed).outcome, "ok");
  assert.equal(source.state.pulls, 2);
  assert.equal(source.state.retires, 1);
  assert.equal(sdk.timers.size, 0);
});

test("short pulls and idle consumers create neither timers nor source read-ahead", { timeout: 3000 }, async t => {
  const sdk = await decoders();
  const source = upstream(["data: first\n\ndata: second\n\n", "data: third\n\n"], "text/event-stream");
  const records = open(t, sdk, source);
  await turn();
  assert.equal(source.state.pulls, 0);
  const reader = records.readable.getReader();
  assert.equal((await reader.read()).value.data, "first");
  await turn();
  assert.equal(source.state.pulls, 1);
  assert.equal(sdk.state.scheduled, 0);
  assert.equal((await reader.read()).value.data, "second");
  assert.equal(source.state.pulls, 1);
  await reader.cancel();
  assert.equal((await records.closed).outcome, "cancelled");
  assert.equal(sdk.timers.size, 0);
});

test("cancel clears a witnessed scheduling wait but still joins both cleanup barriers", { timeout: 3000 }, async t => {
  const tasks = manualTasks(), cancelGate = deferred(), retireGate = deferred();
  const sdk = await decoders(tasks.globals);
  const source = upstream([":\n".repeat(2048) + "data: forbidden\n\n"], "text/event-stream", {
    cancelGate: cancelGate.promise, retireGate: retireGate.promise,
  });
  t.after(() => { cancelGate.resolve(); retireGate.resolve(); tasks.run(); });
  const records = open(t, sdk, source);
  const reading = records.readable.getReader().read();
  void reading.catch(() => {});
  await parked(tasks, reading);
  const pulls = source.state.pulls;
  let settled = false;
  const stopping = records.cancel("cancel parked parser");
  void stopping.then(() => { settled = true; });
  await turn();
  assert.equal(tasks.pending.size, 0, "cancel must remove its scheduler resource before cleanup settles");
  assert.equal(source.state.cancels, 1);
  assert.equal(source.state.retires, 1);
  assert.equal(settled, false);
  cancelGate.resolve();
  await turn();
  assert.equal(settled, false, "operation completion is not the independent retirement receipt");
  retireGate.resolve();
  assert.equal((await stopping).outcome, "cancelled");
  await assert.rejects(reading, error => error.cause?.outcome === "cancelled");
  assert.equal(source.state.pulls, pulls);
});

test("an idle upstream error retires a paused parser without waiting for its timer", { timeout: 3000 }, async t => {
  const tasks = manualTasks(), sdk = await decoders(tasks.globals);
  const source = upstream([":\n".repeat(2048) + "data: forbidden\n\n"], "text/event-stream");
  const records = open(t, sdk, source);
  const reading = records.readable.getReader().read();
  void reading.catch(() => {});
  await parked(tasks, reading);
  source.fail("authoritative upstream failure");
  const receipt = await records.closed;
  assert.equal(receipt.outcome, "err");
  assert.equal(receipt.failure.message, "authoritative upstream failure");
  await assert.rejects(reading, error => error.cause?.failure?.message === "authoritative upstream failure");
  assert.equal(tasks.pending.size, 0);
  assert.equal(source.state.retires, 1);
});

test("timer intrinsics are captured before caller mutation", { timeout: 3000 }, async t => {
  const sdk = await decoders();
  sdk.context.setTimeout = () => { throw new Error("replacement must not run"); };
  sdk.context.clearTimeout = sdk.context.setTimeout;
  const source = upstream([":\n".repeat(512) + "data: intact\n\n"], "text/event-stream");
  const records = open(t, sdk, source);
  const collected = [];
  for await (const record of records.readable) collected.push(record.data);
  assert.deepEqual(collected, ["intact"]);
  assert.ok(sdk.state.scheduled > 0);
  assert.equal(sdk.timers.size, 0);
});

test("minimal timer-free hosts retain their existing decoding compatibility", { timeout: 3000 }, async t => {
  const sdk = await decoders({ setTimeout: undefined, clearTimeout: undefined });
  const source = upstream([":\n".repeat(512) + "data: intact\n\n"], "text/event-stream");
  const records = open(t, sdk, source);
  const collected = [];
  for await (const record of records.readable) collected.push(record.data);
  assert.deepEqual(collected, ["intact"]);
  assert.equal((await records.closed).outcome, "ok");
});

test("scheduler failure is sanitized and still drains the owned source", { timeout: 3000 }, async t => {
  const sdk = await decoders({ setTimeout() { throw new Error("private host payload"); } });
  const source = upstream([":\n".repeat(512) + "data: forbidden\n\n"], "text/event-stream");
  const records = open(t, sdk, source);
  await assert.rejects(records.readable.getReader().read(), error => {
    assert.equal(error.cause?.failure?.code, "compatibility_rejected");
    assert.equal(error.message, "fetch record host scheduling failed");
    return true;
  });
  assert.equal((await records.closed).outcome, "err");
  assert.equal(source.state.cancels, 1);
  assert.equal(source.state.retires, 1);
});

test("fair scanning preserves BOM, UTF-8, CRLF and dispatch over all byte splits", { timeout: 5000 }, async t => {
  const sdk = await decoders();
  const wire = bytes("\ufeffid:α\rdata:😀\r\ndata:second\n\nid:reset\n\n");
  for (let split = 0; split <= wire.length; split += 1) {
    const source = upstream([wire.slice(0, split), wire.slice(split)], "text/event-stream");
    const records = open(t, sdk, source);
    const collected = [];
    for await (const record of records.readable) collected.push(JSON.parse(JSON.stringify(record)));
    assert.deepEqual(collected, [{ type: "message", data: "😀\nsecond", lastEventId: "α" }]);
    assert.equal(records.lastEventId, "reset");
    assert.equal((await records.closed).outcome, "ok");
  }
});

test("byte-budget cuts preserve long UTF-8 lines and CRLF on either side of a yield", { timeout: 5000 }, async t => {
  const sdk = await decoders();
  for (const width of [65_532, 65_533, 65_534, 65_535, 65_536, 65_537]) {
    // The leading BOM, data prefix and multi-byte suffix deliberately shift
    // each delimiter through the scan boundary. No cut is a dispatch boundary.
    const data = "x".repeat(width) + "😀";
    const wire = bytes(`\ufeffdata:${data}\r\nid:next\r\n\r\ndata:tail\n\n`);
    for (const split of [65_535, 65_536, 65_537]) {
      const source = upstream([wire.slice(0, split), wire.slice(split)], "text/event-stream");
      const records = open(t, sdk, source, "sse", { maxLineBytes: 70_000 });
      const collected = [];
      for await (const record of records.readable) collected.push(JSON.parse(JSON.stringify(record)));
      assert.deepEqual(collected, [
        { type: "message", data, lastEventId: "next" },
        { type: "message", data: "tail", lastEventId: "next" },
      ], `line width ${width}, source split ${split}`);
      assert.equal((await records.closed).outcome, "ok");
    }
  }
  assert.ok(sdk.state.fired >= 18, "each long line must actually cross a host-task boundary");
  assert.equal(sdk.timers.size, 0);
});

test("JSON records and an opted-in final tail survive multiple byte-budget yields", { timeout: 5000 }, async t => {
  const sdk = await decoders();
  const value = "😀".repeat(40_000);
  const source = upstream([JSON.stringify(value) + "\r\n" + "\n".repeat(300) + "null"], "application/x-ndjson");
  const records = open(t, sdk, source, "json", { allowFinalRecord: true });
  const collected = [];
  for await (const record of records.readable) collected.push(JSON.parse(JSON.stringify(record)));
  assert.deepEqual(collected, [{ value, lineNumber: 1 }, { value: null, lineNumber: 302 }]);
  assert.equal((await records.closed).outcome, "ok");
  assert.ok(sdk.state.fired >= 3);
  assert.equal(sdk.timers.size, 0);
});

for (const [format, media, wire, options, expected] of [
  ["sse", "text/event-stream", "data:" + "x".repeat(90_000) + "\n\n", { maxLineBytes: 70_000 }, /line exceeds maxLineBytes/],
  ["json", "application/x-ndjson", "\n".repeat(300) + "{", {}, /unterminated final JSON record at line 301/],
  ["json", "application/x-ndjson", "\n".repeat(300) + "{\n", {}, /invalid JSON record at line 301/],
]) {
  test(`yielding does not waive parser errors: ${expected}`, { timeout: 3000 }, async t => {
    const sdk = await decoders();
    const source = upstream([wire], media);
    const records = open(t, sdk, source, format, options);
    await assert.rejects(records.readable.getReader().read(), error => {
      assert.equal(error.cause?.failure?.code, "decode_failure");
      assert.match(error.message, expected);
      return true;
    });
    assert.equal((await records.closed).outcome, "err");
    assert.equal(source.state.retires, 1);
    assert.ok(sdk.state.fired > 0);
    assert.equal(sdk.timers.size, 0);
  });
}

test("native reader cancellation clears a paused pull and exposes failed retirement", { timeout: 3000 }, async t => {
  const tasks = manualTasks(), gate = deferred(), sdk = await decoders(tasks.globals);
  const source = upstream([":\n".repeat(2048) + "data: forbidden\n\n"], "text/event-stream", {
    retireGate: gate.promise, retirement: failure("retirement refused"),
  });
  t.after(() => { gate.resolve(); tasks.run(); });
  const records = open(t, sdk, source), reader = records.readable.getReader();
  const reading = reader.read();
  await parked(tasks, reading);
  let completed = false;
  const stop = reader.cancel("native cancel");
  void stop.then(() => { completed = true; }, () => { completed = true; });
  assert.equal((await reading).done, true, "native Streams immediately end the consumer");
  await turn();
  assert.equal(tasks.pending.size, 0);
  assert.equal(completed, false, "the initiating cancel promise is still a cleanup barrier");
  gate.resolve();
  await assert.rejects(stop, error => error.cause?.failure?.message === "retirement refused");
  const receipt = await records.closed;
  assert.equal(receipt.outcome, "err");
  assert.equal(receipt.failure.message, "retirement refused");
  assert.equal(source.state.cancels, 1);
  assert.equal(source.state.retires, 1);
});

test("a late cleared scheduler callback cannot resurrect the cancelled parser", { timeout: 3000 }, async t => {
  const tasks = manualTasks(), sdk = await decoders(tasks.globals);
  const source = upstream([":\n".repeat(2048) + "data: forbidden\n\n"], "text/event-stream");
  const records = open(t, sdk, source), reader = records.readable.getReader();
  const reading = reader.read();
  void reading.catch(() => {});
  await parked(tasks, reading);
  const callback = [...tasks.pending.values()][0];
  await records.cancel();
  await assert.rejects(reading, error => error.cause?.outcome === "cancelled");
  const pulls = source.state.pulls;
  callback();
  callback();
  await turn();
  assert.equal(source.state.pulls, pulls);
  assert.equal(tasks.pending.size, 0);
  assert.equal(source.state.retires, 1);
});

test("source cancellation re-entering timer registration does not leak its returned timer", { timeout: 3000 }, async t => {
  const tasks = manualTasks();
  let source;
  const sdk = await decoders({
    ...tasks.globals,
    setTimeout(callback) {
      const id = tasks.globals.setTimeout(callback);
      source.fail("upstream failed at timer registration");
      return id;
    },
  });
  source = upstream([":\n".repeat(2048) + "data: forbidden\n\n"], "text/event-stream");
  const records = open(t, sdk, source);
  await assert.rejects(records.readable.getReader().read(), error =>
    error.cause?.failure?.message === "upstream failed at timer registration");
  assert.equal((await records.closed).outcome, "err");
  assert.equal(tasks.pending.size, 0);
  assert.equal(source.state.retires, 1);
});
