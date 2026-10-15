/** Cancellation admission and signal regressions against the actual SDK manager.
 * Uses native Node fetch/streams and an explicit task-ABI double, not a WASM or
 * browser-engine receipt. Run with Node 22.13+ and --experimental-vm-modules.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { getEventListeners } from "node:events";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";

const source = readFileSync(process.env.ASUPERSYNC_FETCH_CANCELLATION_SOURCE
  ?? new URL("../packages/browser/src/fetch.ts", import.meta.url), "utf8");
const code = stripTypeScriptTypes(source, { mode: "transform" });
console.log(JSON.stringify({
  scenario_id: "browser-fetch-cancellation-admission",
  source_sha256: createHash("sha256").update(source).digest("hex"),
  evidence_scope: "actual SDK fetch manager, native streams, task-ABI double",
}));
const turn = () => new Promise((resolve) => setImmediate(resolve));
const deferred = () => {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
};
const ok = (value) => ({ outcome: "ok", value });
const err = (message) => ({ outcome: "err", failure: {
  code: "internal_failure", recoverability: "transient", message,
} });

async function fixture(t, options = {}) {
  const calls = { spawn: [], cancel: [], join: [], fetch: [], schedule: [], clear: [], listen: [], unlisten: [], global: 0 };
  const handles = [];
  const cleanup = [];
  let nextTask = 0;
  let owned = true;
  let closing = false;
  class Handle {
    constructor(raw) { this.raw = { ...raw }; }
    toJSON() { return { ...this.raw }; }
  }
  const exports = {
    Outcome: {
      ok, err: (code, recoverability, message) => ({ outcome: "err", failure: { code, recoverability, message } }),
      cancelled: (cancellation) => ({ outcome: "cancelled", cancellation }),
    },
    RegionHandle: Handle,
    taskSpawn(request) {
      calls.spawn.push(request);
      options.onSpawn?.();
      return options.spawnReceipt ?? ok(new Handle({ kind: "task", slot: ++nextTask, generation: 1, owner_token: "owner" }));
    },
    taskCancel(request) {
      calls.cancel.push(request);
      return options.onCancel?.(request) ?? options.cancelReceipt ?? ok(undefined);
    },
    taskJoin(task, outcome) {
      calls.join.push({ task, outcome });
      return options.onJoin?.(task, outcome) ?? options.joinReceipt ?? outcome;
    },
  };
  // Instrument only the SDK observer; registration still uses native events.
  function ObservedEventTarget() {}
  ObservedEventTarget.prototype = {
    addEventListener(...args) {
      calls.listen.push({ signal: this, listener: args[1] });
      Reflect.apply(EventTarget.prototype.addEventListener, this, args);
      options.onListen?.(this);
    },
    removeEventListener(...args) {
      calls.unlisten.push({ signal: this, listener: args[1] });
      options.onUnlisten?.(this);
      Reflect.apply(EventTarget.prototype.removeEventListener, this, args);
    },
  };
  const context = createContext({ URL, ArrayBuffer, DataView, Uint8Array, AbortSignal,
    EventTarget: ObservedEventTarget, ...options.globals });
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
  const scope = new Handle({ kind: "region", slot: 1, generation: 1, owner_token: "owner" });
  const scopeKey = browserFetchHandleKey(scope.toJSON());
  const grant = { rootKey: "runtime:1", authority: prepareBrowserFetchAuthority({
    allowedOrigins: [options.origin ?? "https://example.test"], allowedMethods: ["GET", "POST"], maxHeaderCount: 4,
  }) };
  const host = {
    AbortController,
    fetch(url, init) {
      calls.fetch.push({ url, init });
      if (options.fetch) return options.fetch(url, init, calls.fetch.length - 1);
      return new Promise((_resolve, reject) => {
        if (init.signal.aborted) reject(new Error("aborted"));
        else init.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
      });
    },
    setTimeout(callback, duration) {
      const id = calls.schedule.length;
      calls.schedule.push({ callback, duration, id });
      options.schedule?.(callback, duration, id);
      return id;
    },
    clearTimeout(id) { calls.clear.push(id); },
  };
  const manager = createBrowserFetchManager({
    lookup: (key) => {
      options.onLookup?.(calls.spawn.length);
      return owned && key === scopeKey ? grant : null;
    },
    isClosing: () => options.isClosing?.(closing, calls.spawn.length) ?? closing,
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
  return {
    calls, handles, cleanup, host, manager, scopeKey, start,
    setClosing(value = true) { closing = value; },
    releaseOwner() { owned = false; },
    fire(index = 0) { calls.schedule[index].callback(); },
  };
}

test("closure beginning inside task admission never starts host I/O", { timeout: 3000 }, async (t) => {
  let f;
  let drain;
  f = await fixture(t, { onSpawn() {
    f.setClosing();
    // The owner's drain snapshot is taken before this operation is registered.
    drain = f.manager.drainScopes(new Set([f.scopeKey]), "scope_close");
  } });
  const admitted = f.start();
  assert.equal(admitted.outcome, "ok", "the already-spawned task still receives an owned handle");
  assert.equal(f.calls.global, 0);
  assert.equal(f.calls.fetch.length, 0);
  assert.equal((await drain).outcome, "ok");
  const outcome = await admitted.value.closed;
  assert.equal(outcome.outcome, "cancelled");
  assert.equal(outcome.cancellation.kind, "scope_close");
  assert.equal(f.calls.cancel.length, 1);
  assert.equal(f.calls.join.length, 1, "closing, unlike released, still owns its ABI task");
});

test("an owner released during admission is not joined a second time", { timeout: 3000 }, async (t) => {
  let f;
  f = await fixture(t, { onSpawn() { f.releaseOwner(); } });
  const handle = f.start().value;
  assert.equal(f.calls.global, 0);
  assert.equal((await handle.closed).cancellation.kind, "scope_close");
  assert.equal(f.calls.cancel.length, 0);
  assert.equal(f.calls.join.length, 0);
});

for (const throwing of [false, true]) {
  test(`synchronous deadline refusal${throwing ? " by throw" : ""} cannot race a fetch`, { timeout: 3000 }, async (t) => {
    const refusal = err("cancel admission refused");
    const f = await fixture(t, {
      schedule(callback) { callback(); },
      onCancel() { if (throwing) throw new Error("cancel admission refused"); return refusal; },
    });
    const handle = f.start({ timeoutMs: 1 }).value;
    assert.equal(f.calls.fetch.length, 0);
    const outcome = await handle.closed;
    assert.equal(outcome.outcome, "err");
    assert.match(outcome.failure.message, /cancel admission refused/);
    assert.equal(f.calls.cancel.length, 1);
    assert.equal(f.calls.join.length, 1);
    assert.deepEqual(f.calls.clear, [0]);
  });
}

test("explicit cancellation refusal remains retryable", { timeout: 3000 }, async (t) => {
  let refuse = true;
  const f = await fixture(t, { onCancel: () => refuse ? err("retry cancellation") : ok(undefined) });
  const handle = f.start().value;
  assert.equal((await handle.cancel()).outcome, "err");
  assert.equal(f.calls.fetch[0].init.signal.aborted, false);
  assert.equal(f.calls.join.length, 0);
  refuse = false;
  assert.equal((await handle.cancel()).outcome, "cancelled");
  assert.equal(f.calls.cancel.length, 2);
  assert.equal(f.calls.join.length, 1);
});

test("a deadline reentered during explicit cancellation makes refusal fail closed", { timeout: 3000 }, async (t) => {
  let f;
  f = await fixture(t, { onCancel() { f.fire(); return err("shared cancellation refused"); } });
  const handle = f.start({ timeoutMs: 1 }).value;
  const receipt = handle.cancel();
  assert.equal(f.calls.fetch[0].init.signal.aborted, true, "implicit refusal must stop synchronously");
  assert.equal((await receipt).outcome, "err");
  assert.equal((await handle.closed).outcome, "err");
  assert.equal(f.calls.cancel.length, 1, "reentrancy coalesces one ABI request");
  assert.equal(f.calls.join.length, 1);
});

test("closing admission refuses fail closed rather than inventing cancellation", { timeout: 3000 }, async (t) => {
  let f;
  f = await fixture(t, { onSpawn() { f.setClosing(); }, cancelReceipt: err("close refused") });
  const handle = f.start().value;
  assert.equal(f.calls.fetch.length, 0);
  const outcome = await handle.closed;
  assert.equal(outcome.outcome, "err");
  assert.match(outcome.failure.message, /close refused/);
  assert.equal(f.calls.join.length, 1);
});

for (const check of ["lookup", "isClosing"]) {
  test(`throwing ${check} after spawn still drains the admitted task`, { timeout: 3000 }, async (t) => {
    const f = await fixture(t, {
      ...(check === "lookup" ? {
        onLookup(spawned) { if (spawned) throw new Error("owner lookup failed"); },
      } : {
        isClosing(_closing, spawned) { if (spawned) throw new Error("owner close check failed"); return false; },
      }),
    });
    const admitted = f.start();
    assert.equal(admitted.outcome, "ok");
    assert.equal(f.calls.global, 0);
    const outcome = await admitted.value.closed;
    assert.equal(outcome.outcome, "err");
    assert.equal(f.calls.join.length, 1);
  });
}

test("publication refusal after closed admission retains credit and surfaces in drain", { timeout: 3000 }, async (t) => {
  let f;
  f = await fixture(t, {
    onSpawn() { f.setClosing(); },
    joinReceipt: err("publication refused"),
  });
  const handle = f.start().value;
  assert.equal(f.calls.fetch.length, 0);
  assert.equal((await handle.closed).failure.message, "publication refused");
  assert.equal((await f.manager.drainScopes(new Set([f.scopeKey]), "scope_close")).outcome, "err");
});

for (const signal of [false, 1, "signal", {}, new EventTarget()]) {
  test(`invalid signal ${Object.prototype.toString.call(signal)} refuses before admission`, { timeout: 3000 }, async (t) => {
    const f = await fixture(t);
    const result = f.start({ signal });
    assert.equal(result.outcome, "err");
    assert.equal(result.failure.code, "compatibility_rejected");
    assert.match(result.failure.message, /signal/);
    assert.equal(f.calls.spawn.length, 0);
    assert.equal(f.calls.global, 0);
  });
}

for (const signal of [undefined, null]) {
  test(`omitted/null signal ${String(signal)} needs no observer support`, { timeout: 3000 }, async (t) => {
    const f = await fixture(t, {
      globals: { AbortSignal: undefined, EventTarget: undefined },
      fetch: () => new Response(null),
    });
    const handle = f.start({ signal }).value;
    assert.equal((await handle.closed).outcome, "ok");
    assert.equal(f.calls.listen.length, 0);
  });
}

for (const missing of ["AbortSignal", "EventTarget"]) {
  test(`missing ${missing} refuses only the opt-in signal path`, { timeout: 3000 }, async (t) => {
    const f = await fixture(t, { globals: { [missing]: undefined } });
    const result = f.start({ signal: new AbortController().signal });
    assert.equal(result.outcome, "err");
    assert.equal(result.failure.code, "compatibility_rejected");
    assert.equal(f.calls.spawn.length, 0);
    assert.equal(f.calls.global, 0);
  });
}

test("pre-aborted signal preserves its reason and prevents every host effect", { timeout: 3000 }, async (t) => {
  const controller = new AbortController();
  controller.abort("navigation superseded");
  const f = await fixture(t);
  const handle = f.start({ signal: controller.signal, timeoutMs: 1 }).value;
  assert.equal(f.calls.global, 0);
  assert.equal(f.calls.fetch.length, 0);
  assert.equal(f.calls.schedule.length, 0);
  const outcome = await handle.closed;
  assert.equal(outcome.outcome, "cancelled");
  assert.equal(outcome.cancellation.kind, "fetch_cancel");
  assert.equal(outcome.cancellation.message, "navigation superseded");
  assert.equal(await handle.response(), outcome);
  assert.equal(await handle.read(), outcome);
  assert.equal(Object.isFrozen(outcome.cancellation), true);
  assert.equal(f.calls.cancel.length, 1);
  assert.equal(f.calls.join.length, 1);
  assert.equal(f.calls.listen.length, 0, "already-aborted signals need no listener");
});

test("pre-aborted signal refusal fails before network I/O without claiming cancellation", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { cancelReceipt: err("signal cancellation refused") });
  const handle = f.start({ signal: AbortSignal.abort("stop") }).value;
  assert.equal(f.calls.global, 0);
  const outcome = await handle.closed;
  assert.equal(outcome.outcome, "err");
  assert.equal(outcome.failure.message, "signal cancellation refused");
  assert.equal(f.calls.join.length, 1);
});

test("an abort during task spawn is observed before host I/O", { timeout: 3000 }, async (t) => {
  const controller = new AbortController();
  const f = await fixture(t, { onSpawn() { controller.abort("cancel during spawn"); } });
  const handle = f.start({ signal: controller.signal }).value;
  assert.equal(f.calls.global, 0);
  assert.equal((await handle.closed).cancellation.message, "cancel during spawn");
});

test("source abort cancels a fetch parked before headers and releases its observer", { timeout: 3000 }, async (t) => {
  const controller = new AbortController();
  const f = await fixture(t);
  const handle = f.start({ signal: controller.signal }).value;
  assert.equal(f.calls.fetch[0].init.signal.aborted, false);
  controller.abort("leave page");
  assert.equal(f.calls.fetch[0].init.signal.aborted, true);
  const outcome = await handle.closed;
  assert.equal(outcome.cancellation.message, "leave page");
  assert.equal(await handle.response(), outcome);
  assert.equal(f.calls.cancel.length, 1);
  assert.equal(f.calls.join.length, 1);
  assert.equal(f.calls.unlisten.length, 1);
  assert.equal(getEventListeners(f.calls.listen[0].signal, "abort").length, 0);
});

test("source abort during a pending read waits for slow native stream cleanup", { timeout: 3000 }, async (t) => {
  const controller = new AbortController();
  const release = deferred();
  let cancellations = 0;
  const body = new ReadableStream({ cancel() { cancellations += 1; return release.promise; } });
  const f = await fixture(t, { fetch: () => new Response(body) });
  f.cleanup.push(release.resolve);
  const handle = f.start({ signal: controller.signal }).value;
  assert.equal((await handle.response()).outcome, "ok");
  const pending = handle.read();
  await turn();
  controller.abort("stop reading");
  assert.equal((await pending).cancellation.message, "stop reading");
  let settled = false;
  void handle.closed.then(() => { settled = true; });
  await turn();
  assert.equal(cancellations, 1);
  assert.equal(settled, false);
  assert.equal(f.calls.join.length, 0);
  release.resolve();
  assert.equal((await handle.closed).outcome, "cancelled");
  assert.equal(body.locked, false);
  assert.equal(f.calls.join.length, 1);
});

test("an idle response body is cancelled without requiring a read", { timeout: 3000 }, async (t) => {
  const controller = new AbortController();
  let cancellations = 0;
  const f = await fixture(t, { fetch: () => new Response(new ReadableStream({
    cancel() { cancellations += 1; },
  })) });
  const handle = f.start({ signal: controller.signal }).value;
  await handle.response();
  controller.abort();
  assert.equal((await handle.closed).outcome, "cancelled");
  assert.equal(cancellations, 1);
});

test("a late response remains owned until its body finishes cancelling", { timeout: 3000 }, async (t) => {
  const controller = new AbortController();
  const delivered = deferred();
  const drained = deferred();
  let cancellations = 0;
  const body = new ReadableStream({ cancel() { cancellations += 1; return drained.promise; } });
  const response = new Response(body);
  const f = await fixture(t, { fetch: () => delivered.promise });
  f.cleanup.push(() => delivered.resolve(response), drained.resolve);
  const handle = f.start({ signal: controller.signal }).value;
  controller.abort("late response");
  assert.equal((await handle.response()).outcome, "cancelled");
  let settled = false;
  void handle.closed.then(() => { settled = true; });
  await turn();
  assert.equal(settled, false);
  delivered.resolve(response);
  await turn();
  assert.equal(cancellations, 1);
  assert.equal(settled, false);
  assert.equal(f.calls.join.length, 0);
  drained.resolve();
  assert.equal((await handle.closed).cancellation.message, "late response");
  assert.equal(f.calls.join.length, 1);
});

test("normal EOF removes the observer and cannot be replaced by a late abort", { timeout: 3000 }, async (t) => {
  const controller = new AbortController();
  const f = await fixture(t, { fetch: () => new Response(new Uint8Array([1, 2, 3])) });
  const handle = f.start({ signal: controller.signal }).value;
  assert.equal((await handle.read()).value.done, false);
  assert.equal((await handle.read()).value.done, true);
  const outcome = await handle.closed;
  assert.equal(outcome.outcome, "ok");
  assert.equal(getEventListeners(f.calls.listen[0].signal, "abort").length, 0);
  controller.abort("too late");
  assert.equal(await handle.closed, outcome);
  assert.equal(f.calls.cancel.length, 0);
  assert.equal(f.calls.join.length, 1);
});

for (const winner of ["network", "deadline", "caller", "scope"]) {
  test(`${winner} terminal outcome wins over a later signal abort`, { timeout: 3000 }, async (t) => {
    const controller = new AbortController();
    const f = await fixture(t, winner === "network" ? { fetch() { throw new Error("network failed"); } } : {});
    const handle = f.start({ signal: controller.signal, timeoutMs: 10 }).value;
    if (winner === "deadline") f.fire();
    if (winner === "caller") void handle.cancel("manual first");
    if (winner === "scope") f.manager.closeScopes(new Set([f.scopeKey]), "scope_close");
    const outcome = await handle.closed;
    const cancelled = f.calls.cancel.length;
    assert.equal(getEventListeners(f.calls.listen[0].signal, "abort").length, 0);
    controller.abort("signal lost");
    assert.equal(await handle.closed, outcome);
    assert.equal(f.calls.cancel.length, cancelled);
    assert.equal(controller.signal.reason, "signal lost", "SDK teardown does not abort caller signals");
  });
}

test("a signal winning the race makes queued timer callbacks inert", { timeout: 3000 }, async (t) => {
  const controller = new AbortController();
  const f = await fixture(t);
  const handle = f.start({ signal: controller.signal, timeoutMs: 10 }).value;
  controller.abort("signal first");
  f.fire();
  const outcome = await handle.closed;
  assert.equal(outcome.cancellation.kind, "fetch_cancel");
  assert.equal(outcome.cancellation.message, "signal first");
  assert.equal(f.calls.cancel.length, 1);
  assert.deepEqual(f.calls.clear, [0]);
});

test("forged source abort events neither cancel nor consume the real observer", { timeout: 3000 }, async (t) => {
  const controller = new AbortController();
  const f = await fixture(t);
  const handle = f.start({ signal: controller.signal }).value;
  controller.signal.dispatchEvent(new Event("abort"));
  await turn();
  assert.equal(f.calls.cancel.length, 0);
  assert.equal(f.calls.fetch[0].init.signal.aborted, false);
  controller.abort("actual abort");
  assert.equal((await handle.closed).cancellation.message, "actual abort");
});

test("another source listener cannot suppress owned cancellation", { timeout: 3000 }, async (t) => {
  const controller = new AbortController();
  controller.signal.addEventListener("abort", (event) => event.stopImmediatePropagation());
  const f = await fixture(t);
  const handle = f.start({ signal: controller.signal }).value;
  controller.abort("cannot suppress");
  assert.equal((await handle.closed).cancellation.message, "cannot suppress");
});

test("caller method overrides cannot capture or suppress the private observer", { timeout: 3000 }, async (t) => {
  const controller = new AbortController();
  Object.defineProperties(controller.signal, {
    addEventListener: { value() { throw new Error("shadow add"); } },
    removeEventListener: { value() { throw new Error("shadow remove"); } },
  });
  const f = await fixture(t);
  const result = f.start({ signal: controller.signal });
  assert.equal(result.outcome, "ok");
  controller.abort("native reason");
  assert.equal((await result.value.closed).cancellation.message, "native reason");
});

test("explicit cancellation of one consumer does not abort a shared signal", { timeout: 3000 }, async (t) => {
  const controller = new AbortController();
  const f = await fixture(t);
  const first = f.start({ signal: controller.signal }).value;
  const second = f.start({ signal: controller.signal }).value;
  await first.cancel("only first");
  assert.equal(controller.signal.aborted, false);
  assert.equal(f.calls.fetch[1].init.signal.aborted, false);
  controller.abort("shared cancellation");
  assert.equal((await second.closed).cancellation.message, "shared cancellation");
  assert.equal((await first.closed).cancellation.message, "only first");
  assert.equal(f.calls.cancel.length, 2);
  assert.equal(f.calls.join.length, 2);
});

test("composed caller signals retain the first source reason", { timeout: 3000 }, async (t) => {
  const first = new AbortController();
  const second = new AbortController();
  const f = await fixture(t);
  const handle = f.start({ signal: AbortSignal.any([first.signal, second.signal]) }).value;
  second.abort("second source");
  first.abort("first source too late");
  assert.equal((await handle.closed).cancellation.message, "second source");
  assert.equal(f.calls.cancel.length, 1);
});

test("observer registration failure is drained without starting host I/O", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { onListen() { throw new Error("observer registration failed"); } });
  const handle = f.start({ signal: new AbortController().signal }).value;
  assert.equal(f.calls.global, 0);
  assert.equal((await handle.closed).outcome, "err");
  assert.equal(getEventListeners(f.calls.listen[0].signal, "abort").length, 0);
  assert.equal(f.calls.join.length, 1);
});

test("an abort reentered during observer registration prevents host I/O", { timeout: 3000 }, async (t) => {
  const controller = new AbortController();
  const f = await fixture(t, { onListen() { controller.abort("during observer registration"); } });
  const handle = f.start({ signal: controller.signal }).value;
  assert.equal(f.calls.global, 0);
  assert.equal((await handle.closed).cancellation.message, "during observer registration");
  assert.equal(f.calls.cancel.length, 1);
  assert.equal(f.calls.join.length, 1);
});

test("throwing observer removal cannot retain an active callback or change success", { timeout: 3000 }, async (t) => {
  const controller = new AbortController();
  const f = await fixture(t, {
    onUnlisten() { throw new Error("remove failed"); },
    fetch: () => new Response(null),
  });
  const handle = f.start({ signal: controller.signal }).value;
  assert.equal((await handle.closed).outcome, "ok");
  f.calls.listen[0].listener();
  controller.abort("after success");
  assert.equal(f.calls.cancel.length, 0);
  assert.equal(f.calls.join.length, 1);
});

test("a reason that throws during rendering still produces a typed cancellation", { timeout: 3000 }, async (t) => {
  const controller = new AbortController();
  const f = await fixture(t);
  const handle = f.start({ signal: controller.signal }).value;
  controller.abort({ toString() { throw new Error("cannot render reason"); } });
  const outcome = await handle.closed;
  assert.equal(outcome.outcome, "cancelled");
  assert.equal(outcome.cancellation.message, "unprintable host error");
});

test("a signal reentered during explicit ABI refusal makes the shared request fail closed", { timeout: 3000 }, async (t) => {
  const controller = new AbortController();
  const f = await fixture(t, { onCancel() {
    controller.abort("implicit cancellation");
    return err("shared signal request refused");
  } });
  const handle = f.start({ signal: controller.signal }).value;
  const receipt = handle.cancel();
  assert.equal(f.calls.fetch[0].init.signal.aborted, true);
  assert.equal((await receipt).outcome, "err");
  assert.equal((await handle.closed).failure.message, "shared signal request refused");
  assert.equal(f.calls.cancel.length, 1);
});

test("signal cleanup holds runtime credit until the last host resource settles", { timeout: 3000 }, async (t) => {
  const controller = new AbortController();
  const release = deferred();
  const f = await fixture(t, { fetch: (_url, _init, index) => new Response(new ReadableStream({
    cancel() { if (index === 0) return release.promise; },
  })) });
  f.cleanup.push(release.resolve);
  const first = f.start({ signal: controller.signal }).value;
  await first.response();
  for (let index = 1; index < 64; index += 1) assert.equal(f.start().outcome, "ok");
  assert.equal(f.start().outcome, "err");
  controller.abort("release one slot");
  await turn();
  assert.equal(f.start().outcome, "err", "abort is not drain completion");
  release.resolve();
  await first.closed;
  assert.equal(f.start().outcome, "ok");
  assert.equal(f.start().outcome, "err", "exactly one credit is recycled");
});

test("signal publication refusal retains the task and blocks a successful owner drain", { timeout: 3000 }, async (t) => {
  const controller = new AbortController();
  const f = await fixture(t, { joinReceipt: err("signal publication refused") });
  const handle = f.start({ signal: controller.signal }).value;
  controller.abort("cannot publish");
  assert.equal((await handle.closed).failure.message, "signal publication refused");
  for (let index = 1; index < 64; index += 1) assert.equal(f.start().outcome, "ok");
  assert.equal(f.start().outcome, "err");
  assert.equal((await f.manager.drainScopes(new Set([f.scopeKey]), "scope_close")).outcome, "err");
});

test("caller abort closes a real HTTP peer with a stalled response body", { timeout: 5000 }, async (t) => {
  const peerClosed = deferred();
  const server = createServer((_request, response) => {
    response.on("close", peerClosed.resolve);
    response.writeHead(200, { "content-type": "application/octet-stream" });
    response.write(Buffer.from([7]));
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  const origin = `http://127.0.0.1:${server.address().port}`;
  const controller = new AbortController();
  const f = await fixture(t, { origin, fetch: (url, init) => fetch(url, init) });
  const handle = f.start({ signal: controller.signal }).value;
  assert.equal((await handle.response()).outcome, "ok");
  assert.deepEqual(Array.from((await handle.read()).value.value), [7]);
  const parked = handle.read();
  controller.abort("disconnect peer");
  assert.equal((await parked).cancellation.message, "disconnect peer");
  assert.equal((await handle.closed).outcome, "cancelled");
  await peerClosed.promise;
  assert.equal(f.calls.cancel.length, 1);
  assert.equal(f.calls.join.length, 1);
});

test("pre-aborted native state cannot be hidden by shadow properties", { timeout: 3000 }, async (t) => {
  const controller = new AbortController();
  controller.abort("actual reason");
  Object.defineProperties(controller.signal, {
    aborted: { value: false }, reason: { value: "forged reason" },
  });
  const f = await fixture(t);
  const handle = f.start({ signal: controller.signal }).value;
  assert.equal(f.calls.global, 0);
  assert.equal((await handle.closed).cancellation.message, "actual reason");
});

test("host composition cannot fabricate an abort for an intrinsically live source", { timeout: 3000 }, async (t) => {
  const controller = new AbortController();
  Object.defineProperties(controller.signal, {
    aborted: { value: true }, reason: { value: "forged reason" },
  });
  const f = await fixture(t);
  // Node's native any() consults these properties; its inconsistent clone is
  // rejected, not published as a cancellation of the actual source.
  assert.equal(f.start({ signal: controller.signal }).outcome, "err");
  assert.equal(f.calls.spawn.length, 0);
  assert.equal(f.calls.global, 0);
});

test("an abort reentered during host signal composition cannot be missed", { timeout: 3000 }, async (t) => {
  const controller = new AbortController();
  Object.defineProperty(controller.signal, "aborted", {
    get() { controller.abort("abort during composition"); return false; },
  });
  const f = await fixture(t);
  const handle = f.start({ signal: controller.signal }).value;
  assert.equal(f.calls.global, 0);
  assert.equal((await handle.closed).cancellation.message, "abort during composition");
});
