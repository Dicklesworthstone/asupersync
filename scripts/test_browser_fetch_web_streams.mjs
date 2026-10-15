/** Actual SDK fetch -> native WHATWG streams, including localhost HTTP.
 * The task ABI is an explicit double: not a Rust/WASM integration receipt.
 * Run: node --experimental-vm-modules --test scripts/test_browser_fetch_web_streams.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";

const source = readFileSync(process.env.ASUPERSYNC_FETCH_STREAM_SOURCE
  ?? new URL("../packages/browser/src/fetch.ts", import.meta.url), "utf8");
const code = stripTypeScriptTypes(source, { mode: "transform" });
console.log(JSON.stringify({ scenario_id: "browser-fetch-native-web-streams",
  source_sha256: createHash("sha256").update(source).digest("hex"),
  evidence_scope: "actual SDK fetch manager, native WHATWG streams, localhost HTTP, task-ABI double" }));
const ok = (value) => ({ outcome: "ok", value });
const refused = (message) => ({ outcome: "err", failure: {
  code: "internal_failure", recoverability: "transient", message,
} });
const deferred = () => {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
};
const turn = () => new Promise((resolve) => setImmediate(resolve));

async function fixture(t, options = {}) {
  const calls = { fetch: [], cancel: [], join: [], timers: [] };
  const handles = [];
  const cleanup = [];
  let sequence = 0;
  class Handle {
    constructor(value) { this.value = value; }
    toJSON() { return { ...this.value }; }
  }
  const exports = {
    Outcome: { ok, err: (code, recoverability, message) => ({ outcome: "err", failure: { code, recoverability, message } }),
      cancelled: (cancellation) => ({ outcome: "cancelled", cancellation }) },
    RegionHandle: Handle,
    taskSpawn: () => ok(new Handle({ kind: "task", slot: ++sequence, generation: 1, owner_token: "owner" })),
    taskCancel(request) { calls.cancel.push(request); return options.cancelReceipt ?? ok(undefined); },
    taskJoin(task, outcome) { calls.join.push({ task, outcome }); return options.joinReceipt ?? outcome; },
  };
  const context = createContext({ URL, ArrayBuffer, DataView, Uint8Array, AbortSignal, EventTarget,
    ReadableStream, ...options.globals });
  const abi = new SyntheticModule(Object.keys(exports), function () {
    for (const [name, value] of Object.entries(exports)) this.setExport(name, value);
  }, { context });
  const module = new SourceTextModule(code, { context });
  await module.link((name) => { assert.equal(name, "@asupersync/browser-core"); return abi; });
  await module.evaluate();
  const { createBrowserFetchManager, prepareBrowserFetchAuthority, browserFetchHandleKey } = module.namespace;
  const scope = new Handle({ kind: "region", slot: 1, generation: 1, owner_token: "owner" });
  const scopeKey = browserFetchHandleKey(scope.toJSON());
  const origin = options.origin ?? "https://example.test";
  const grant = { rootKey: "runtime:1", authority: prepareBrowserFetchAuthority({
    allowedOrigins: [origin], allowedMethods: ["GET"], maxHeaderCount: 0,
  }) };
  const host = {
    AbortController,
    fetch(url, init) {
      calls.fetch.push({ url, init });
      return options.fetch ? options.fetch(url, init) : new Response(options.body ?? null);
    },
    setTimeout(callback) { calls.timers.push(callback); return calls.timers.length; },
    clearTimeout() {},
  };
  const manager = createBrowserFetchManager({ lookup: (key) => key === scopeKey ? grant : null,
    isClosing: () => false, globalObject: () => host });
  const start = (extra = {}) => {
    const result = manager.start(scope, { url: `${origin}/data`, ...extra }, null);
    if (result.outcome === "ok") handles.push(result.value);
    return result;
  };
  t.after(async () => {
    for (const release of cleanup) release();
    manager.closeScopes(new Set([scopeKey]), "fixture_cleanup");
    await Promise.all(handles.map((handle) => handle.closed));
  });
  const stream = (handle) => {
    assert.equal(typeof handle.toReadableStream, "function", "owned fetch must expose native stream consumption");
    const result = handle.toReadableStream();
    assert.equal(result.outcome, "ok");
    assert.ok(result.value instanceof ReadableStream);
    return result.value;
  };
  return { calls, handles, cleanup, start, stream, manager, scopeKey };
}

function chunks(values, counters = {}) {
  let index = 0;
  return new ReadableStream({
    pull(controller) {
      counters.pulls = (counters.pulls ?? 0) + 1;
      if (index < values.length) controller.enqueue(Uint8Array.from(values[index++]));
      else controller.close();
    },
    cancel(reason) { counters.cancels = (counters.cancels ?? 0) + 1; counters.reason = reason; },
  }, { highWaterMark: 0 });
}

function expectFailure(promise, outcome, pattern) {
  return assert.rejects(promise, (error) => {
    assert.equal(error.cause?.outcome, outcome);
    if (pattern) assert.match(error.message, pattern);
    return true;
  });
}

test("conversion is memoized, exclusive, and does not prefetch", { timeout: 3000 }, async (t) => {
  const count = {};
  const f = await fixture(t, { body: chunks([[1], [2]], count) });
  const handle = f.start().value;
  const stream = f.stream(handle);
  assert.equal(f.stream(handle), stream);
  await handle.response();
  await turn();
  assert.equal(count.pulls ?? 0, 0);
  assert.equal((await handle.read()).failure.code, "compatibility_rejected");
  const reader = stream.getReader();
  assert.deepEqual(Array.from((await reader.read()).value), [1]);
  await turn();
  assert.equal(count.pulls, 1, "no read-ahead after delivering a chunk");
  assert.deepEqual(Array.from((await reader.read()).value), [2]);
  assert.equal((await reader.read()).done, true);
  assert.equal((await handle.closed).outcome, "ok");
  assert.equal(f.calls.join.length, 1);
  reader.releaseLock();
});

test("pending manual reads refuse transfer; completed reads leave the unread tail", { timeout: 3000 }, async (t) => {
  const ready = deferred();
  let read = 0;
  const body = new ReadableStream({ async pull(controller) {
    read += 1;
    if (read === 1) { await ready.promise; controller.enqueue(new Uint8Array([4])); }
    else if (read === 2) controller.enqueue(new Uint8Array([5]));
    else controller.close();
  } }, { highWaterMark: 0 });
  const f = await fixture(t, { body });
  f.cleanup.push(ready.resolve);
  const handle = f.start().value;
  const first = handle.read();
  assert.equal(handle.toReadableStream().failure.recoverability, "transient");
  ready.resolve();
  assert.deepEqual(Array.from((await first).value.value), [4]);
  const remaining = await new Response(f.stream(handle)).arrayBuffer();
  assert.deepEqual(Array.from(new Uint8Array(remaining)), [5]);
});

test("Response consumers preserve fragmented bytes, including empty chunks", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { body: chunks([[], [0, 255], [], [3, 4]]) });
  const handle = f.start().value;
  const bytes = await new Response(f.stream(handle)).arrayBuffer();
  assert.deepEqual(Array.from(new Uint8Array(bytes)), [0, 255, 3, 4]);
  assert.equal((await handle.closed).outcome, "ok");
});

test("native decoding pipelines handle split UTF-8 code points", { timeout: 3000 }, async (t) => {
  const bytes = new TextEncoder().encode("snowman: ☃; emoji: 😀");
  const f = await fixture(t, { body: chunks(Array.from(bytes, (byte) => [byte])) });
  const handle = f.start().value;
  let text = "";
  await f.stream(handle).pipeThrough(new TextDecoderStream()).pipeTo(new WritableStream({
    write(chunk) { text += chunk; },
  }));
  assert.equal(text, "snowman: ☃; emoji: 😀");
  assert.equal(f.calls.cancel.length, 0);
  assert.equal(f.calls.join.length, 1);
});

test("pipeTo backpressure stops SDK pulls while the destination write is held", { timeout: 3000 }, async (t) => {
  const count = {};
  const writing = deferred();
  const release = deferred();
  const f = await fixture(t, { body: chunks([[1], [2]], count) });
  f.cleanup.push(release.resolve);
  const handle = f.start().value;
  const received = [];
  const piping = f.stream(handle).pipeTo(new WritableStream({ async write(value) {
    received.push(...value);
    if (received.length === 1) { writing.resolve(); await release.promise; }
  } }));
  await writing.promise;
  await turn();
  assert.equal(count.pulls, 1);
  assert.equal(f.calls.join.length, 0);
  release.resolve();
  await piping;
  assert.deepEqual(received, [1, 2]);
  assert.equal((await handle.closed).outcome, "ok");
});

test("native reader cancellation awaits pending read and delayed source cleanup", { timeout: 3000 }, async (t) => {
  const release = deferred();
  let cancelled = 0;
  const body = new ReadableStream({ cancel() { cancelled += 1; return release.promise; } }, { highWaterMark: 0 });
  const f = await fixture(t, { body });
  f.cleanup.push(release.resolve);
  const handle = f.start().value;
  const reader = f.stream(handle).getReader();
  const pending = reader.read();
  await turn();
  let drained = false;
  const cancelling = reader.cancel("consumer stopped").then(() => { drained = true; });
  assert.equal((await pending).done, true, "native cancellation closes the consumer immediately");
  await turn();
  assert.equal(cancelled, 1);
  assert.equal(drained, false, "cancel() completion, unlike read EOF, is the cleanup barrier");
  assert.equal(f.calls.join.length, 0);
  release.resolve();
  await cancelling;
  assert.equal(body.locked, false);
  assert.equal((await handle.closed).cancellation.message, "consumer stopped");
  assert.equal(f.calls.join.length, 1);
  reader.releaseLock();
});

test("breaking async iteration waits for owned fetch cleanup", { timeout: 3000 }, async (t) => {
  const release = deferred();
  const entered = deferred();
  const body = new ReadableStream({ pull(controller) { controller.enqueue(new Uint8Array([9])); },
    cancel() { entered.resolve(); return release.promise; } }, { highWaterMark: 0 });
  const f = await fixture(t, { body });
  f.cleanup.push(release.resolve);
  const handle = f.start().value;
  let finished = false;
  const iteration = (async () => { for await (const value of f.stream(handle)) {
    assert.deepEqual(Array.from(value), [9]); break;
  } finished = true; })();
  await entered.promise;
  await turn();
  assert.equal(finished, false);
  assert.equal(f.calls.join.length, 0);
  release.resolve();
  await iteration;
  assert.equal((await handle.closed).outcome, "cancelled");
  assert.equal(body.locked, false);
});

test("cancel before headers retains late host responses until their cleanup settles", { timeout: 3000 }, async (t) => {
  const response = deferred();
  const release = deferred();
  let cancels = 0;
  const body = new ReadableStream({ cancel() { cancels += 1; return release.promise; } });
  const late = new Response(body);
  const f = await fixture(t, { fetch: () => response.promise });
  f.cleanup.push(() => response.resolve(late), release.resolve);
  const handle = f.start().value;
  let finished = false;
  const cancellation = f.stream(handle).cancel("late response").then(() => { finished = true; });
  await turn();
  assert.equal(finished, false);
  response.resolve(late);
  await turn();
  assert.equal(cancels, 1);
  assert.equal(finished, false);
  release.resolve();
  await cancellation;
  assert.equal(f.calls.join.length, 1);
});

for (const mode of ["signal", "deadline", "handle", "scope"]) {
  test(`${mode} cancellation errors an idle native reader with the terminal Outcome`, { timeout: 3000 }, async (t) => {
    const controller = new AbortController();
    const release = deferred();
    const body = new ReadableStream({ cancel() { return release.promise; } });
    const f = await fixture(t, { body });
    f.cleanup.push(release.resolve);
    const handle = f.start({ signal: controller.signal, timeoutMs: 10 }).value;
    const reader = f.stream(handle).getReader();
    let errored = false;
    const readerClosed = expectFailure(reader.closed, "cancelled").then(() => { errored = true; });
    await handle.response();
    if (mode === "signal") controller.abort("external abort");
    if (mode === "deadline") f.calls.timers[0]();
    if (mode === "handle") void handle.cancel("direct abort");
    if (mode === "scope") f.manager.closeScopes(new Set([f.scopeKey]), "scope_close");
    await turn();
    assert.equal(errored, false, "external failure is published after cleanup, even without a pending pull");
    release.resolve();
    await readerClosed;
    await expectFailure(reader.read(), "cancelled");
    assert.equal(body.locked, false);
    reader.releaseLock();
  });
}

test("body limits error the native consumer only after source cleanup", { timeout: 3000 }, async (t) => {
  const release = deferred();
  const body = new ReadableStream({ pull(controller) { controller.enqueue(new Uint8Array([1, 2])); },
    cancel() { return release.promise; } }, { highWaterMark: 0 });
  const f = await fixture(t, { body });
  f.cleanup.push(release.resolve);
  const handle = f.start({ maxResponseBytes: 1 }).value;
  const reader = f.stream(handle).getReader();
  const closed = expectFailure(reader.closed, "err", /bytes exceed/);
  let rejected = false;
  const reading = expectFailure(reader.read(), "err", /bytes exceed/).then(() => { rejected = true; });
  await turn();
  assert.equal(rejected, false);
  assert.equal(f.calls.join.length, 0);
  release.resolve();
  await Promise.all([reading, closed]);
  assert.equal(f.calls.fetch[0].init.signal.aborted, true);
  assert.equal(f.calls.join.length, 1);
  reader.releaseLock();
});

test("terminal publication refusal prevents a successful native pipe completion", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { body: chunks([[1]]), joinReceipt: refused("publication refused") });
  const handle = f.start().value;
  const values = [];
  await expectFailure(f.stream(handle).pipeTo(new WritableStream({ write(value) { values.push(...value); } })),
    "err", /publication refused/);
  assert.deepEqual(values, [1]);
  assert.equal((await f.manager.drainScopes(new Set([f.scopeKey]), "scope_close")).outcome, "err");
});

for (const failure of ["cancel", "join"]) {
  test(`${failure} refusal rejects native cancellation after cleanup without releasing a retained task`, { timeout: 3000 }, async (t) => {
    const release = deferred();
    const body = new ReadableStream({ cancel() { return release.promise; } });
    const f = await fixture(t, { body, [failure === "cancel" ? "cancelReceipt" : "joinReceipt"]: refused(`${failure} refused`) });
    f.cleanup.push(release.resolve);
    const handle = f.start().value;
    const stream = f.stream(handle);
    await handle.response();
    let rejected = false;
    const cancellation = expectFailure(stream.cancel("stop consumer"), "err", /refused/).then(() => { rejected = true; });
    await turn();
    assert.equal(rejected, false);
    assert.equal(f.calls.fetch[0].init.signal.aborted, true);
    release.resolve();
    await cancellation;
    assert.equal(body.locked, false);
    assert.equal(f.calls.join.length, 1);
    if (failure === "join") assert.equal((await f.manager.drainScopes(new Set([f.scopeKey]), "scope_close")).outcome, "err");
  });
}

test("missing native streams refuse conversion without taking manual read ownership", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { body: chunks([[6]]), globals: { ReadableStream: undefined } });
  const handle = f.start().value;
  const result = handle.toReadableStream();
  assert.equal(result.outcome, "err");
  assert.equal(result.failure.code, "compatibility_rejected");
  assert.deepEqual(Array.from((await handle.read()).value.value), [6]);
  assert.equal((await handle.read()).value.done, true);
});

test("throwing stream construction restores manual consumption", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { body: chunks([[8]]), globals: { ReadableStream: class {
    constructor() { throw new Error("constructor unavailable"); }
  } } });
  const handle = f.start().value;
  assert.equal(handle.toReadableStream().outcome, "err");
  assert.deepEqual(Array.from((await handle.read()).value.value), [8]);
  assert.equal((await handle.read()).value.done, true);
});

test("bodyless responses expose a closed native stream", { timeout: 3000 }, async (t) => {
  const f = await fixture(t);
  const handle = f.start().value;
  await handle.closed;
  assert.equal(await new Response(f.stream(handle)).text(), "");
  assert.equal(f.calls.cancel.length, 0);
  assert.equal(f.calls.join.length, 1);
});

test("preexisting network errors remain typed when conversion happens after closure", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { fetch() { throw new Error("network down"); } });
  const handle = f.start().value;
  const terminal = await handle.closed;
  const reader = f.stream(handle).getReader();
  const closed = expectFailure(reader.closed, "err", /network down/);
  await assert.rejects(reader.read(), (error) => error.cause === terminal);
  await closed;
  reader.releaseLock();
});

test("a rejected destination cancels and drains the fetch before pipeTo rejects", { timeout: 3000 }, async (t) => {
  const release = deferred();
  const cancelled = deferred();
  const body = new ReadableStream({ pull(controller) { controller.enqueue(new Uint8Array([1])); },
    cancel() { cancelled.resolve(); return release.promise; } }, { highWaterMark: 0 });
  const f = await fixture(t, { body });
  f.cleanup.push(release.resolve);
  const handle = f.start().value;
  let rejected = false;
  const piping = assert.rejects(f.stream(handle).pipeTo(new WritableStream({
    write() { throw new Error("destination failed"); },
  })), /destination failed/).then(() => { rejected = true; });
  await cancelled.promise;
  await turn();
  assert.equal(rejected, false);
  assert.equal(f.calls.join.length, 0);
  release.resolve();
  await piping;
  assert.equal((await handle.closed).outcome, "cancelled");
  assert.equal(body.locked, false);
});

test("pipeTo AbortSignal reaches a parked source and waits for its cancellation", { timeout: 3000 }, async (t) => {
  const controller = new AbortController();
  const release = deferred();
  const body = new ReadableStream({ cancel() { return release.promise; } }, { highWaterMark: 0 });
  const f = await fixture(t, { body });
  f.cleanup.push(release.resolve);
  const handle = f.start().value;
  let sinkAborts = 0;
  let rejected = false;
  const piping = assert.rejects(f.stream(handle).pipeTo(new WritableStream({
    abort() { sinkAborts += 1; },
  }), { signal: controller.signal }), /pipe abort/).then(() => { rejected = true; });
  await handle.response();
  await turn();
  controller.abort(new Error("pipe abort"));
  await turn();
  assert.equal(rejected, false);
  assert.equal(sinkAborts, 1);
  assert.equal(f.calls.fetch[0].init.signal.aborted, true);
  release.resolve();
  await piping;
  assert.equal((await handle.closed).outcome, "cancelled");
});

test("actual HTTP response streams through the SDK into a native JSON consumer", { timeout: 5000 }, async (t) => {
  let requests = 0;
  const server = createServer((_request, response) => {
    requests += 1;
    response.writeHead(200, { "content-type": "application/json" });
    response.write('{"message":"');
    setImmediate(() => response.end('hello ☃","values":[1,2,3]}'));
  });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  t.after(async () => { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); });
  const origin = `http://127.0.0.1:${server.address().port}`;
  const f = await fixture(t, { origin, fetch: (url, init) => fetch(url, init) });
  const handle = f.start().value;
  assert.deepEqual(await new Response(f.stream(handle)).json(), { message: "hello ☃", values: [1, 2, 3] });
  assert.equal((await handle.response()).value.status, 200);
  assert.equal((await handle.closed).outcome, "ok");
  assert.equal(requests, 1);
  assert.equal(f.calls.join.length, 1);
});

test("repeated native cancel is not a substitute for the initiating cleanup barrier", { timeout: 3000 }, async (t) => {
  const release = deferred();
  const f = await fixture(t, { body: new ReadableStream({ cancel() { return release.promise; } }) });
  f.cleanup.push(release.resolve);
  const handle = f.start().value;
  const stream = f.stream(handle);
  await handle.response();
  let finished = false;
  const first = stream.cancel("first cancellation").then(() => { finished = true; });
  await stream.cancel("already closed");
  await turn();
  assert.equal(finished, false, "native repeated cancel resolves early by WHATWG design");
  assert.equal(f.calls.join.length, 0);
  release.resolve();
  await first;
  assert.equal((await handle.closed).cancellation.message, "first cancellation");
  assert.equal(f.calls.cancel.length, 1);
});

test("native stream cancellation holds runtime admission until its source drains", { timeout: 3000 }, async (t) => {
  const release = deferred();
  let sequence = 0;
  const f = await fixture(t, { fetch() {
    const index = sequence++;
    return new Response(new ReadableStream({ cancel() { if (index === 0) return release.promise; } }));
  } });
  f.cleanup.push(release.resolve);
  const handle = f.start().value;
  const stream = f.stream(handle);
  await handle.response();
  for (let i = 1; i < 64; i += 1) assert.equal(f.start().outcome, "ok");
  const cancellation = stream.cancel();
  await turn();
  assert.equal(f.start().outcome, "err");
  release.resolve();
  await cancellation;
  assert.equal(f.start().outcome, "ok");
  assert.equal(f.start().outcome, "err", "exactly one admission is released");
});

test("aborting a native pipe disconnects a real HTTP peer with a stalled body", { timeout: 5000 }, async (t) => {
  const peerClosed = deferred();
  const delivered = deferred();
  const server = createServer((_request, response) => {
    response.on("close", peerClosed.resolve);
    response.writeHead(200, { "content-type": "application/octet-stream" });
    response.write(Buffer.from([7]));
  });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  t.after(async () => { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); });
  const origin = `http://127.0.0.1:${server.address().port}`;
  const f = await fixture(t, { origin, fetch: (url, init) => fetch(url, init) });
  const handle = f.start().value;
  const abort = new AbortController();
  const piping = assert.rejects(f.stream(handle).pipeTo(new WritableStream({ write(bytes) {
    assert.deepEqual(Array.from(bytes), [7]); delivered.resolve();
  } }), { signal: abort.signal }), /disconnect pipeline/);
  await delivered.promise;
  abort.abort(new Error("disconnect pipeline"));
  await piping;
  await peerClosed.promise;
  assert.equal((await handle.closed).outcome, "cancelled");
  assert.equal(f.calls.cancel.length, 1);
  assert.equal(f.calls.join.length, 1);
});
