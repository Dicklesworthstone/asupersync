/** Host-side fetch deadline regressions: actual SDK manager, native streams,
 * virtual/real timers, localhost HTTP and an intentional task-ABI double. Not a
 * Rust/WASM or browser-engine receipt. Node 22.13+ and --experimental-vm-modules.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";

const sourcePath = process.env.ASUPERSYNC_FETCH_DEADLINE_SOURCE
  ?? new URL("../packages/browser/src/fetch.ts", import.meta.url);
const source = readFileSync(sourcePath, "utf8");
const code = stripTypeScriptTypes(source, { mode: "transform" });
console.log(JSON.stringify({
  scenario_id: "browser-fetch-owned-deadlines",
  plan_work_package: "R33",
  source_sha256: createHash("sha256").update(source).digest("hex"),
  evidence_scope: "actual SDK fetch manager, native streams, virtual/real timers, localhost HTTP, task-ABI double",
}));
const turn = () => new Promise((resolve) => setImmediate(resolve));
const deferred = () => {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
};
const ok = (value) => ({ outcome: "ok", value });
const err = (message) => ({ outcome: "err", failure: { code: "internal_failure", recoverability: "transient", message } });

async function fixture(t, options = {}) {
  const calls = { spawn: [], cancel: [], join: [], fetch: [], schedule: [], clear: [], global: 0 };
  const cleanup = [];
  const handles = [];
  const timers = new Map();
  let nextTask = 0;
  let nextTimer = 0;
  class Handle {
    constructor(raw) { this.raw = { ...raw }; }
    toJSON() { return { ...this.raw }; }
  }
  const exports = {
    Outcome: { ok, err: (code, recoverability, message) => ({ outcome: "err", failure: { code, recoverability, message } }),
      cancelled: (cancellation) => ({ outcome: "cancelled", cancellation }) },
    RegionHandle: Handle,
    taskSpawn(request) {
      calls.spawn.push(request);
      return options.spawnReceipt ?? ok(new Handle({ kind: "task", slot: ++nextTask, generation: 1, owner_token: "fetch-owner" }));
    },
    taskCancel(request) {
      calls.cancel.push(request);
      return options.onCancel?.(request) ?? options.cancelReceipt ?? ok(undefined);
    },
    taskJoin(task, outcome) {
      calls.join.push({ task, outcome });
      return options.joinReceipt ?? outcome;
    },
  };
  const context = createContext({ URL, ArrayBuffer, DataView, Uint8Array });
  const abi = new SyntheticModule(Object.keys(exports), function () {
    for (const [name, value] of Object.entries(exports)) this.setExport(name, value);
  }, { context });
  const module = new SourceTextModule(code, { context });
  await module.link((specifier) => {
    assert.equal(specifier, "@asupersync/browser-core");
    return abi;
  });
  await module.evaluate();
  const { createBrowserFetchManager, prepareBrowserFetchAuthority, browserFetchHandleKey } = module.namespace;
  const scope = new Handle({ kind: "region", slot: 1, generation: 1, owner_token: "fetch-owner" });
  const scopeKey = browserFetchHandleKey(scope.toJSON());
  const grant = { rootKey: "runtime:1", authority: prepareBrowserFetchAuthority({
    allowedOrigins: [options.origin ?? "https://example.test"], allowedMethods: ["GET", "POST"], maxHeaderCount: 4,
  }) };
  const host = {
    AbortController,
    fetch(url, init) {
      assert.equal(this, host);
      calls.fetch.push({ url, init });
      if (options.fetch) return options.fetch(url, init, calls.fetch.length - 1);
      return new Promise((resolve, reject) => {
        if (init.signal.aborted) reject(new Error("aborted"));
        else init.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
      });
    },
    setTimeout(callback, duration) {
      assert.equal(this, host, "timer host binding");
      const id = nextTimer++;
      calls.schedule.push({ id, callback, duration });
      timers.set(id, callback);
      options.schedule?.(callback, duration, id);
      return id;
    },
    clearTimeout(id) {
      assert.equal(this, host, "clear host binding");
      calls.clear.push(id);
      timers.delete(id);
      options.clear?.(id);
    },
  };
  const manager = createBrowserFetchManager({
    lookup: (key) => key === scopeKey ? grant : null,
    isClosing: () => false,
    globalObject: () => { calls.global += 1; return host; },
  });
  const start = (extra = {}) => {
    const result = manager.start(scope, { url: `${options.origin ?? "https://example.test"}/data`, ...extra }, null);
    if (result.outcome === "ok") handles.push(result.value);
    return result;
  };
  t.after(async () => {
    for (const release of cleanup) release();
    manager.closeScopes(new Set([scopeKey]), "fixture_cleanup");
    await Promise.all(handles.map((handle) => handle.closed));
  });
  return { calls, cleanup, handles, timers, manager, scopeKey, start, host,
    fire(index = 0) {
      assert.ok(calls.schedule[index], "a deadline must be scheduled");
      calls.schedule[index].callback();
    } };
}

for (const timeoutMs of [-1, 0.5, NaN, Infinity, 2_147_483_648, null, "5"]) {
  test(`invalid timeout ${String(timeoutMs)} refuses before admission`, { timeout: 3000 }, async (t) => {
    const f = await fixture(t);
    const result = f.start({ timeoutMs });
    assert.equal(result.outcome, "err");
    assert.match(result.failure.message, /timeoutMs/);
    assert.equal(f.calls.spawn.length, 0);
    assert.equal(f.calls.global, 0);
  });
}

test("omitted deadline does not acquire timer authority", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { fetch: () => new Response(null) });
  Object.defineProperty(f.host, "setTimeout", { get() { throw new Error("timer access is forbidden"); } });
  const handle = f.start().value;
  assert.equal((await handle.response()).outcome, "ok");
  assert.equal((await handle.closed).outcome, "ok");
  assert.equal(f.calls.schedule.length, 0);
});

test("zero deadline cancels before any host I/O or timer lookup", { timeout: 3000 }, async (t) => {
  const f = await fixture(t);
  const handle = f.start({ timeoutMs: 0 }).value;
  assert.equal(f.calls.global, 0);
  assert.equal(f.calls.fetch.length, 0);
  assert.equal(f.calls.schedule.length, 0);
  const result = await handle.closed;
  assert.equal(result.outcome, "cancelled");
  assert.equal(result.cancellation.kind, "deadline");
  assert.equal((await handle.response()), result);
  assert.equal(f.calls.cancel.length, 1);
  assert.equal(f.calls.join.length, 1);
});

test("expiry aborts a fetch parked before headers and publishes one cancellation", { timeout: 3000 }, async (t) => {
  const f = await fixture(t);
  const handle = f.start({ timeoutMs: 25 }).value;
  assert.equal(f.calls.schedule[0]?.duration, 25);
  assert.equal(f.calls.fetch.length, 1);
  f.fire();
  const outcome = await handle.closed;
  assert.equal(outcome.outcome, "cancelled");
  assert.equal(outcome.cancellation.kind, "deadline");
  assert.match(outcome.cancellation.message, /25 ms/);
  assert.equal(f.calls.fetch[0].init.signal.aborted, true);
  assert.equal(await handle.response(), outcome);
  assert.equal(await handle.read(), outcome);
  f.fire();
  assert.equal(f.calls.cancel.length, 1);
  assert.equal(f.calls.join.length, 1);
  assert.deepEqual(f.calls.clear, [0], "zero-valued timer handles are still cleared");
});

test("headers do not end the deadline and cleanup is not reported early", { timeout: 3000 }, async (t) => {
  const release = deferred();
  let cancelled = 0;
  const body = new ReadableStream({ cancel() { cancelled += 1; return release.promise; } });
  const f = await fixture(t, { fetch: () => new Response(body) });
  f.cleanup.push(release.resolve);
  const handle = f.start({ timeoutMs: 10 }).value;
  assert.equal((await handle.response()).outcome, "ok");
  const reading = handle.read();
  await turn();
  f.fire();
  assert.equal((await reading).outcome, "cancelled");
  let closed = false;
  void handle.closed.then(() => { closed = true; });
  await turn();
  assert.equal(cancelled, 1);
  assert.equal(closed, false, "slow host cancellation still owns the operation");
  assert.equal(f.calls.join.length, 0);
  release.resolve();
  assert.equal((await handle.closed).outcome, "cancelled");
  assert.equal(body.locked, false);
  assert.equal(f.calls.join.length, 1);
});

test("idle response bodies expire without a read call", { timeout: 3000 }, async (t) => {
  let cancelled = 0;
  const f = await fixture(t, { fetch: () => new Response(new ReadableStream({ cancel() { cancelled += 1; } })) });
  const handle = f.start({ timeoutMs: 10 }).value;
  await handle.response();
  f.fire();
  assert.equal((await handle.closed).outcome, "cancelled");
  assert.equal(cancelled, 1);
});

test("EOF clears its deadline and a stale callback cannot change success", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { fetch: () => new Response(new Uint8Array([1, 2, 3])) });
  const handle = f.start({ timeoutMs: 10 }).value;
  assert.equal(f.calls.schedule.length, 1);
  assert.equal((await handle.read()).value.done, false);
  assert.equal((await handle.read()).value.done, true);
  const outcome = await handle.closed;
  assert.equal(outcome.outcome, "ok");
  assert.deepEqual(f.calls.clear, [0]);
  f.fire();
  assert.equal(await handle.closed, outcome);
  assert.equal(f.calls.cancel.length, 0);
});

test("bodyless responses clear their deadline at completion", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { fetch: () => new Response(null, { status: 204 }) });
  const handle = f.start({ timeoutMs: 10 }).value;
  assert.equal(f.calls.schedule.length, 1);
  assert.equal((await handle.closed).outcome, "ok");
  assert.equal(f.timers.size, 0);
  f.fire();
  assert.equal(f.calls.cancel.length, 0);
});

test("network failure wins over a later deadline", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { fetch() { throw new Error("network failure"); } });
  const handle = f.start({ timeoutMs: 10 }).value;
  assert.equal(f.calls.schedule.length, 1);
  const outcome = await handle.closed;
  assert.equal(outcome.outcome, "err");
  assert.match(outcome.failure.message, /network failure/);
  f.fire();
  assert.equal(await handle.closed, outcome);
  assert.equal(f.calls.cancel.length, 0);
  assert.equal(f.timers.size, 0);
});

test("caller cancellation wins and removes the deadline", { timeout: 3000 }, async (t) => {
  const f = await fixture(t);
  const handle = f.start({ timeoutMs: 10 }).value;
  assert.equal(f.calls.schedule.length, 1);
  const outcome = await handle.cancel("caller first");
  assert.equal(outcome.cancellation.kind, "fetch_cancel");
  f.fire();
  assert.equal(await handle.closed, outcome);
  assert.equal(f.calls.cancel.length, 1);
  assert.equal(f.timers.size, 0);
});

test("scope teardown removes deadlines without cancelling a retired task", { timeout: 3000 }, async (t) => {
  const f = await fixture(t);
  const handle = f.start({ timeoutMs: 10 }).value;
  assert.equal(f.calls.schedule.length, 1);
  f.manager.closeScopes(new Set([f.scopeKey]), "scope_close");
  const outcome = await handle.closed;
  assert.equal(outcome.cancellation.kind, "scope_close");
  f.fire();
  assert.equal(f.calls.cancel.length, 0);
  assert.equal(f.calls.join.length, 0);
  assert.equal(f.timers.size, 0);
});

test("implicit cancellation refusal fails the operation instead of ignoring expiry", { timeout: 3000 }, async (t) => {
  const refusal = err("cancellation refused by ABI");
  const f = await fixture(t, { cancelReceipt: refusal });
  const handle = f.start({ timeoutMs: 10 }).value;
  f.fire();
  const outcome = await handle.closed;
  assert.equal(outcome.outcome, "err");
  assert.equal(outcome.failure.message, refusal.failure.message);
  assert.equal(f.calls.fetch[0].init.signal.aborted, true);
  assert.equal(f.calls.join.length, 1);
});

for (const missing of ["setTimeout", "clearTimeout"]) {
  test(`missing ${missing} fails before network I/O`, { timeout: 3000 }, async (t) => {
    const f = await fixture(t);
    f.host[missing] = undefined;
    const handle = f.start({ timeoutMs: 10 }).value;
    assert.equal(f.calls.fetch.length, 0);
    const result = await handle.closed;
    assert.equal(result.outcome, "err");
    assert.equal(result.failure.code, "compatibility_rejected");
    assert.equal(f.calls.cancel.length, 0);
  });
}

test("a throwing timer scheduler fails closed before fetch", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { schedule() { throw new Error("schedule unavailable"); } });
  const handle = f.start({ timeoutMs: 10 }).value;
  assert.equal(f.calls.fetch.length, 0);
  const outcome = await handle.closed;
  assert.equal(outcome.outcome, "err");
  assert.match(outcome.failure.message, /schedule unavailable/);
  f.fire();
  assert.equal(f.calls.cancel.length, 0, "a retained callback is inert after failure");
});

test("synchronous expiry during scheduling still releases the returned timer", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { schedule(callback) { callback(); } });
  const handle = f.start({ timeoutMs: 10 }).value;
  assert.equal(f.calls.fetch.length, 0);
  assert.equal((await handle.closed).outcome, "cancelled");
  assert.deepEqual(f.calls.clear, [0]);
  assert.equal(f.timers.size, 0);
});

test("a throwing timer clear cannot replace the terminal outcome", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { clear() { throw new Error("clear failed"); } });
  const handle = f.start({ timeoutMs: 10 }).value;
  f.fire();
  const outcome = await handle.closed;
  assert.equal(outcome.outcome, "cancelled");
  f.fire();
  assert.equal(f.calls.cancel.length, 1);
  assert.equal(await handle.closed, outcome);
});

test("request credit remains held until deadline cleanup drains", { timeout: 3000 }, async (t) => {
  const release = deferred();
  const f = await fixture(t, { fetch: (_url, _init, index) => new Response(new ReadableStream({
    cancel() { return index === 0 ? release.promise : undefined; },
  })) });
  f.cleanup.push(release.resolve);
  const first = f.start({ timeoutMs: 10 }).value;
  await first.response();
  for (let index = 1; index < 64; index += 1) assert.equal(f.start().outcome, "ok");
  assert.equal(f.start().outcome, "err");
  f.fire();
  await turn();
  assert.equal(f.start().outcome, "err", "abort alone must not recycle capacity");
  release.resolve();
  await first.closed;
  assert.equal(f.start().outcome, "ok", "completed cleanup recycles exactly one slot");
});

test("terminal publication refusal retains the expired task's admission", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { joinReceipt: err("terminal publication refused") });
  const first = f.start({ timeoutMs: 10 }).value;
  f.fire();
  assert.equal((await first.closed).failure.message, "terminal publication refused");
  for (let index = 1; index < 64; index += 1) assert.equal(f.start().outcome, "ok");
  assert.equal(f.start().outcome, "err");
  const drain = await f.manager.drainScopes(new Set([f.scopeKey]), "scope_close");
  assert.equal(drain.outcome, "err");
});

test("the maximum timer duration is passed without signed overflow", { timeout: 3000 }, async (t) => {
  const f = await fixture(t);
  const handle = f.start({ timeoutMs: 2_147_483_647 }).value;
  assert.equal(f.calls.schedule[0]?.duration, 2_147_483_647);
  await handle.cancel();
});

test("a deadline refusal is immutable while host abort cleanup is still pending", { timeout: 3000 }, async (t) => {
  const held = deferred();
  const refusal = err("deadline admission refused");
  const f = await fixture(t, {
    cancelReceipt: refusal,
    fetch: (_url, init) => new Promise((resolve, reject) => {
      init.signal.addEventListener("abort", () => {
        void held.promise.then(() => reject(new Error("aborted")));
      }, { once: true });
    }),
  });
  f.cleanup.push(held.resolve);
  const handle = f.start({ timeoutMs: 5 }).value;
  f.fire();
  const response = await handle.response();
  assert.equal(response, refusal);
  assert.equal(Object.isFrozen(response), true);
  assert.equal(Object.isFrozen(response.failure), true);
  assert.throws(() => { response.failure.message = "forged success"; }, TypeError);
  assert.equal(f.calls.join.length, 0, "cleanup still owns the task");
  held.resolve();
  const closed = await handle.closed;
  assert.equal(closed, refusal);
  assert.equal(closed.failure.message, "deadline admission refused");
});

test("host abort-insensitive fetch retains ownership until its late body is drained", { timeout: 3000 }, async (t) => {
  const delivered = deferred();
  const drained = deferred();
  let cancels = 0;
  const f = await fixture(t, { fetch: () => delivered.promise });
  const body = new ReadableStream({ cancel() { cancels += 1; return drained.promise; } });
  const response = new Response(body);
  f.cleanup.push(() => delivered.resolve(response), drained.resolve);
  const handle = f.start({ timeoutMs: 5 }).value;
  f.fire();
  assert.equal((await handle.response()).outcome, "cancelled");
  let closed = false;
  void handle.closed.then(() => { closed = true; });
  await turn();
  assert.equal(closed, false);
  assert.equal(f.calls.join.length, 0);
  delivered.resolve(response);
  await turn();
  assert.equal(cancels, 1);
  assert.equal(closed, false, "a late response body must finish cancelling");
  drained.resolve();
  assert.equal((await handle.closed).cancellation.kind, "deadline");
  assert.equal(f.calls.join.length, 1);
});

test("real host timer delivers expiry without a caller polling the handle", { timeout: 3000 }, async (t) => {
  const f = await fixture(t);
  let scheduled = 0;
  f.host.setTimeout = (...args) => { scheduled += 1; return setTimeout(...args); };
  f.host.clearTimeout = clearTimeout;
  const handle = f.start({ timeoutMs: 1 }).value;
  assert.equal(scheduled, 1);
  const outcome = await handle.closed;
  assert.equal(outcome.outcome, "cancelled");
  assert.equal(outcome.cancellation.kind, "deadline");
  assert.equal(f.calls.fetch[0].init.signal.aborted, true);
  assert.equal(f.calls.cancel.length, 1);
  assert.equal(f.calls.join.length, 1);
});

test("deadline abort reaches a real HTTP peer while its response body is stalled", { timeout: 3000 }, async (t) => {
  const peerClosed = deferred();
  let requested = 0;
  const server = createServer((_request, response) => {
    requested += 1;
    response.on("close", peerClosed.resolve);
    response.writeHead(200, { "content-type": "application/octet-stream" });
    response.write(Buffer.from([7]));
    // Deliberately never end: the client's abort must close this response.
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const origin = `http://127.0.0.1:${server.address().port}`;
  const f = await fixture(t, { origin, fetch: (url, init) => fetch(url, init) });
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  const handle = f.start({ timeoutMs: 100 }).value;
  assert.equal((await handle.response()).outcome, "ok");
  const first = await handle.read();
  assert.equal(first.outcome, "ok");
  assert.deepEqual(Array.from(first.value.value), [7]);
  const parked = handle.read();
  f.fire();
  assert.equal((await parked).cancellation.kind, "deadline");
  assert.equal((await handle.closed).cancellation.kind, "deadline");
  await peerClosed.promise;
  assert.equal(requested, 1);
  assert.equal(f.calls.join.length, 1);
});
