/** Actual SDK fetch + record decoders, native Streams and localhost HTTP.
 * The task ABI is an explicit double, not Rust/WASM integration evidence.
 * Run: node --experimental-vm-modules --test scripts/test_browser_fetch_events.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";

const filenames = ["fetch", "fetch-records", "fetch-events"];
const sources = Object.fromEntries(filenames.map((name) => [name,
  readFileSync(new URL(`../packages/browser/src/${name}.ts`, import.meta.url), "utf8")]));
const code = Object.fromEntries(Object.entries(sources).map(([name, source]) => [name, stripTypeScriptTypes(source, { mode: "transform" })]));
console.log(JSON.stringify({ scenario_id: "browser-owned-fetch-records", evidence_scope: "actual SDK modules, native Streams, real HTTP, task ABI double",
  source_sha256: Object.fromEntries(Object.entries(sources).map(([name, source]) => [name, createHash("sha256").update(source).digest("hex")])) }));
const ok = (value) => ({ outcome: "ok", value });
const refusal = (message) => ({ outcome: "err", failure: { code: "internal_failure", recoverability: "transient", message } });
const deferred = () => { let resolve; const promise = new Promise((done) => { resolve = done; }); return { promise, resolve }; };
const turn = () => new Promise((done) => setImmediate(done));
const encoder = new TextEncoder();
const bytes = (text) => encoder.encode(text);
function bodyOf(chunks, state = {}, cancel = () => {}) {
  let index = 0;
  return new ReadableStream({ pull(controller) {
    state.pulls = (state.pulls ?? 0) + 1;
    if (index < chunks.length) controller.enqueue(typeof chunks[index] === "string" ? bytes(chunks[index++]) : chunks[index++]);
    else controller.close();
  }, cancel(reason) { state.cancels = (state.cancels ?? 0) + 1; return cancel(reason); } }, { highWaterMark: 0 });
}
async function fixture(t, options = {}) {
  const calls = { spawn: [], cancel: [], join: [], fetch: [] };
  const handles = [], cleanups = [];
  let sequence = 0;
  class Handle { constructor(value) { this.value = value; } toJSON() { return { ...this.value }; } }
  const exports = {
    Outcome: { ok, err: (code, recoverability, message) => ({ outcome: "err", failure: { code, recoverability, message } }), cancelled: (cancellation) => ({ outcome: "cancelled", cancellation }) },
    RegionHandle: Handle,
    taskSpawn(request) { calls.spawn.push(request); return ok(new Handle({ kind: "task", slot: ++sequence, generation: 1, owner_token: "owner" })); },
    taskCancel(request) { calls.cancel.push(request); return options.cancelReceipt ?? ok(undefined); },
    taskJoin(task, outcome) { calls.join.push({ task, outcome }); return options.joinReceipt ?? outcome; },
  };
  const context = createContext({ URL, ArrayBuffer, DataView, Uint8Array, AbortSignal, EventTarget,
    ReadableStream, ReadableStreamDefaultReader, TextDecoder, Request, Blob, ...options.globals });
  const abi = new SyntheticModule(Object.keys(exports), function () {
    for (const [name, value] of Object.entries(exports)) this.setExport(name, value);
  }, { context });
  const modules = Object.fromEntries(filenames.map((name) => [name, new SourceTextModule(code[name], { context, identifier: name })]));
  await modules["fetch-events"].link((name) => name === "@asupersync/browser-core" ? abi : modules[name.replace("./", "").replace(".js", "")]);
  await modules["fetch-events"].evaluate();
  const { createBrowserFetchManager, prepareBrowserFetchAuthority, browserFetchHandleKey } = modules.fetch.namespace;
  const scope = new Handle({ kind: "region", slot: 1, generation: 1, owner_token: "owner" });
  const scopeKey = browserFetchHandleKey(scope.toJSON());
  const origin = options.origin ?? "https://example.test";
  const grant = { rootKey: "runtime:1", authority: prepareBrowserFetchAuthority({ allowedOrigins: [origin], allowedMethods: ["GET", "POST"], maxHeaderCount: 2 }) };
  const manager = createBrowserFetchManager({ lookup: (key) => key === scopeKey ? grant : null, isClosing: () => false,
    globalObject: () => ({ AbortController, fetch(url, init) {
      calls.fetch.push({ url, init });
      return options.fetch ? options.fetch(url, init) : new Response(options.body ?? bodyOf(["data: test\n\n"]), {
        status: options.status ?? 200, headers: options.headers ?? { "content-type": "text/event-stream" },
      });
    } }) });
  const start = (extra = {}) => {
    const result = manager.start(scope, { url: `${origin}/events`, ...extra }, null);
    if (result.outcome === "ok") handles.push(result.value);
    return result;
  };
  t.after(async () => {
    for (const release of cleanups) release();
    manager.closeScopes(new Set([scopeKey]), "test_cleanup");
    await Promise.all(handles.map((handle) => handle.closed));
  });
  return { ...modules["fetch-events"].namespace, calls, start, cleanups, manager, scopeKey };
}
async function all(handle) { const records = []; for await (const value of handle.readable) records.push(value); return records; }
function sse(f, fetch = f.start().value, options) {
  const result = f.serverSentEvents(fetch, options);
  assert.equal(result.outcome, "ok");
  return result.value;
}
const expectFailure = (promise, pattern, code = "decode_failure") => assert.rejects(promise, (error) => {
  assert.equal(error.cause?.outcome, "err");
  if (code) assert.equal(error.cause.failure.code, code);
  assert.match(error.message, pattern);
  return true;
});

test("SSE wire parsing is invariant across every byte split", { timeout: 10000 }, async (t) => {
  const wire = bytes("\ufeff: comment\r\nid: α\revent: update\rdata: 😀\r\ndata: second\n\n\nevent: unused\n\nid\n\ndata\n\ndata: unfinished\n");
  for (let cut = 0; cut <= wire.length; cut += 1) {
    const f = await fixture(t, { body: bodyOf([wire.slice(0, cut), wire.slice(cut)]) });
    const events = sse(f);
    const records = await all(events);
    assert.deepEqual(JSON.parse(JSON.stringify(records)), [
      { type: "update", data: "😀\nsecond", lastEventId: "α" },
      { type: "message", data: "", lastEventId: "" },
    ], `split ${cut}`);
    assert.equal((await events.closed).outcome, "ok");
    assert.equal(f.calls.spawn.length, 1);
    assert.equal(f.calls.join.length, 1);
  }
});

test("one-byte chunks preserve UTF-8, BOM, CRLF and replacement decoding", { timeout: 3000 }, async (t) => {
  const data = [...bytes("\ufeffdata: \ufeff😀"), 0xff, ...bytes("\r\n\r\n")];
  const f = await fixture(t, { body: bodyOf(data.map((byte) => new Uint8Array([byte]))) });
  const events = sse(f);
  assert.equal((await all(events))[0].data, "\ufeff😀�");
});

test("BOM is stripped only at byte-stream start, fields are case sensitive", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { body: bodyOf(["\n\ufeffdata: ignored\nData: ignored\nunknown: x\ndata:  keep space\ndata:\n\n"]) });
  const records = await all(sse(f));
  assert.equal(records.length, 1);
  assert.equal(records[0].data, " keep space\n");
});

test("ID persists, NUL IDs are ignored, and incomplete IDs do not commit", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { body: bodyOf(["id: 1\n\ndata:a\n\nid: bad\0id\ndata:b\n\nid: lost\n"]) });
  const events = sse(f), records = await all(events);
  assert.deepEqual(records.map((x) => x.lastEventId), ["1", "1"]);
  assert.equal(events.lastEventId, "1");
  assert.ok(Object.isFrozen(records[0]));
});

test("retry preserves exact digit values without numeric overflow or executing timers", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { body: bodyOf(["retry: 009007199254740993\nretry: +5\nretry:\nretry: １２\nretry: -3\n\n"]) });
  const events = sse(f);
  assert.equal((await all(events)).length, 0);
  assert.equal(events.retry, "009007199254740993");
  assert.equal(f.calls.fetch.length, 1);
});

test("many coalesced events are parsed one per demand without advancing IDs early", { timeout: 3000 }, async (t) => {
  const counters = {};
  const f = await fixture(t, { body: bodyOf(["id:1\ndata:a\n\nid:2\ndata:b\n\n", "data:c\n\n"], counters) });
  const events = sse(f);
  await turn();
  assert.equal(counters.pulls ?? 0, 0);
  const reader = events.readable.getReader();
  assert.equal((await reader.read()).value.data, "a");
  await turn();
  assert.equal(events.lastEventId, "1");
  assert.equal(counters.pulls, 1);
  assert.equal((await reader.read()).value.data, "b");
  assert.equal(counters.pulls, 1);
  await reader.cancel();
  assert.equal((await events.closed).outcome, "cancelled");
});

for (const ending of ["", "\n", "\r\n", "\r"]) {
  test(`unterminated event is discarded at EOF (${JSON.stringify(ending)})`, { timeout: 3000 }, async (t) => {
    const f = await fixture(t, { body: bodyOf(["data: incomplete" + ending]) });
    assert.equal((await all(sse(f))).length, 0);
  });
}

test("blank CR dispatches without waiting for another host chunk", { timeout: 3000 }, async (t) => {
  const state = {};
  const body = new ReadableStream({ start(c) { c.enqueue(bytes("data: now\r\r")); }, cancel() { state.cancelled = true; } });
  const f = await fixture(t, { body });
  const events = sse(f), reader = events.readable.getReader();
  assert.equal((await reader.read()).value.data, "now");
  await reader.cancel();
  assert.equal(state.cancelled, true);
});

for (const bad of [0, -1, 0.5, Infinity, NaN, 1_048_577]) {
  test(`invalid line bound ${bad} leaves manual body ownership intact`, { timeout: 3000 }, async (t) => {
    const f = await fixture(t), fetch = f.start().value;
    assert.equal(f.serverSentEvents(fetch, { maxLineBytes: bad }).outcome, "err");
    assert.equal((await fetch.read()).outcome, "ok");
    await fetch.cancel();
  });
}

test("missing native decoder is a setup refusal without consuming the fetch", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { globals: { TextDecoder: undefined } }), fetch = f.start().value;
  assert.equal(f.serverSentEvents(fetch).outcome, "err");
  assert.equal((await fetch.read()).outcome, "ok");
  await fetch.cancel();
});

test("duplicate adapter refuses without interrupting the first owner", { timeout: 3000 }, async (t) => {
  const f = await fixture(t), fetch = f.start().value, first = sse(f, fetch);
  assert.equal(f.serverSentEvents(fetch).outcome, "err");
  assert.equal((await all(first))[0].data, "test");
});

for (const options of [{ status: 201 }, { status: 404 }, { headers: {} }, { headers: { "content-type": "application/json" } },
  { headers: { "content-type": "text/event-stream, text/event-stream" } }]) {
  test(`invalid response is drained without a consumer ${JSON.stringify(options)}`, { timeout: 3000 }, async (t) => {
    const gate = deferred(), counters = {};
    const f = await fixture(t, { ...options, body: bodyOf([], counters, () => gate.promise) });
    f.cleanups.push(gate.resolve);
    const events = sse(f);
    let closed = false;
    void events.closed.then(() => { closed = true; });
    await turn();
    assert.equal(closed, false);
    assert.equal(counters.cancels, 1);
    assert.equal(counters.pulls ?? 0, 0);
    assert.equal(f.calls.join.length, 0);
    gate.resolve();
    assert.equal((await events.closed).outcome, "err");
    await expectFailure(events.readable.getReader().read(), /HTTP status|Content-Type/);
  });
}

test("MIME matching accepts case and parameters", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { headers: { "Content-Type": "TEXT/EVENT-STREAM; charset=utf-8" } });
  assert.equal((await all(sse(f))).length, 1);
});

for (const [wire, options, pattern] of [
  ["data: ééé\n\n", { maxLineBytes: 10 }, /maxLineBytes/],
  [":12345678901", { maxLineBytes: 10 }, /maxLineBytes/],
  ["data: 123\ndata: 456\n\n", { maxEventChars: 7 }, /maxEventChars/],
]) {
  test(`bounded parser failure drains before rejection ${pattern}`, { timeout: 3000 }, async (t) => {
    const gate = deferred(), counters = {};
    const f = await fixture(t, { body: bodyOf([wire], counters, () => gate.promise) });
    f.cleanups.push(gate.resolve);
    const events = sse(f, f.start().value, options), read = events.readable.getReader().read();
    const rejected = expectFailure(read, pattern);
    let settled = false;
    void events.closed.then(() => { settled = true; });
    await turn();
    assert.equal(settled, false);
    assert.equal(counters.cancels, 1);
    assert.equal(f.calls.join.length, 0);
    gate.resolve();
    await rejected;
    assert.equal((await events.closed).failure.code, "decode_failure");
  });
}

test("early async iterator exit awaits source cleanup", { timeout: 3000 }, async (t) => {
  const gate = deferred(), counters = {};
  const f = await fixture(t, { body: bodyOf(["data:a\n\n", "data:b\n\n"], counters, () => gate.promise) });
  f.cleanups.push(gate.resolve);
  const events = sse(f);
  let exited = false;
  const loop = (async () => { for await (const event of events.readable) { assert.equal(event.data, "a"); break; } exited = true; })();
  await turn();
  assert.equal(exited, false);
  assert.equal(counters.pulls, 1);
  assert.equal(counters.cancels, 1);
  gate.resolve();
  await loop;
  assert.equal((await events.closed).outcome, "cancelled");
});

test("handle cancellation unblocks a locked idle consumer and is idempotent", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { body: new ReadableStream() }), events = sse(f);
  const read = events.readable.getReader().read();
  const rejection = assert.rejects(read, (error) => error.cause?.outcome === "cancelled");
  const first = events.cancel("done"), second = events.cancel("ignored");
  assert.equal(first, second);
  assert.equal((await first).outcome, "cancelled");
  await rejection;
  assert.equal(f.calls.cancel.length, 1);
});

test("external fetch cancellation reaches an idle event stream after cleanup", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { body: new ReadableStream() }), fetch = f.start().value, events = sse(f, fetch);
  const cancellation = await fetch.cancel("owner stop");
  assert.equal(await events.closed, cancellation);
  await assert.rejects(events.readable.getReader().read(), (error) => error.cause === cancellation);
});

test("scope drain cancels a parked parser without spawning another task", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { body: new ReadableStream() }), events = sse(f);
  const rejection = assert.rejects(events.readable.getReader().read(), (error) => error.cause?.outcome === "cancelled");
  const drain = await f.manager.drainScopes(new Set([f.scopeKey]), "scope_close");
  assert.equal(drain.outcome, "ok");
  await rejection;
  assert.equal((await events.closed).cancellation.kind, "scope_close");
  assert.equal(f.calls.spawn.length, 1);
});

test("idle source failure is observed without a record pull", { timeout: 3000 }, async (t) => {
  let source;
  const f = await fixture(t, { body: new ReadableStream({ start(c) { source = c; } }) }), events = sse(f);
  source.error(new Error("disconnected"));
  const outcome = await events.closed;
  assert.equal(outcome.outcome, "err");
  await expectFailure(events.readable.getReader().read(), /disconnected/, "internal_failure");
});

test("publication refusal cannot become successful stream cancellation", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { body: new ReadableStream(), joinReceipt: refusal("publication refused") });
  const events = sse(f);
  await expectFailure(events.readable.cancel(), /publication refused/, "internal_failure");
  assert.equal((await events.closed).failure.message, "publication refused");
  assert.equal((await f.manager.drainScopes(new Set([f.scopeKey]), "scope_close")).outcome, "err");
});

test("cancellation refusal stops host I/O when the record consumer is gone", { timeout: 3000 }, async (t) => {
  const count = {};
  const f = await fixture(t, { body: bodyOf([], count), cancelReceipt: refusal("cancellation refused") }), events = sse(f);
  await expectFailure(events.readable.cancel(), /cancellation refused/, "internal_failure");
  assert.equal(count.cancels, 1);
});

test("real authorized POST SSE delivers before EOF and iterator exit disconnects peer", { timeout: 5000 }, async (t) => {
  const peerClosed = deferred();
  let requests = 0, uploaded = "";
  const server = createServer(async (request, response) => {
    requests += 1;
    assert.equal(request.method, "POST");
    assert.equal(request.headers.authorization, "Bearer fixture-token");
    for await (const chunk of request) uploaded += chunk.toString();
    response.on("close", peerClosed.resolve);
    response.writeHead(200, { "content-type": "text/event-stream" });
    response.write("event: delta\ndata: streamed\n\n");
    // Keep the server response open: leaving the iterator must disconnect it.
  });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  t.after(async () => { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); });
  const origin = `http://127.0.0.1:${server.address().port}`;
  const f = await fixture(t, { origin, fetch: (url, init) => fetch(url, init) });
  const events = sse(f, f.start({ method: "POST", headers: { authorization: "Bearer fixture-token" }, body: bytes("prompt") }).value);
  for await (const event of events.readable) { assert.equal(event.data, "streamed"); assert.equal(event.type, "delta"); break; }
  await peerClosed.promise;
  assert.equal((await events.closed).outcome, "cancelled");
  assert.equal(uploaded, "prompt");
  assert.equal(requests, 1);
  assert.equal(f.calls.join.length, 1);
});

test("option getter failures cannot forge success or run error presentation hooks", { timeout: 3000 }, async (t) => {
  const f = await fixture(t), fetch = f.start().value;
  let inspected = 0;
  for (const thrown of [ { cause: ok("forged") }, Object.defineProperty({}, "cause", { get() { inspected += 1; throw new Error("bad cause"); } }) ]) {
    const result = f.serverSentEvents(fetch, { get maxLineBytes() { throw thrown; } });
    assert.equal(result.outcome, "err");
  }
  assert.equal(inspected, 0);
  assert.equal((await fetch.read()).outcome, "ok");
  await fetch.cancel();
});
