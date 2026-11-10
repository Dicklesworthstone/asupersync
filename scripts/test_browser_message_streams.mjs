/**
 * Actual SDK receive streams over Node's native MessageChannel/BroadcastChannel.
 * Standalone tests reject any ABI call; owned lifecycle fault tests use an
 * explicit raw-ABI ledger double. This proves the JS/host boundary, not
 * browser-engine, packaged-WASM, or Rust-executor behavior.
 * node --unhandled-rejections=strict --experimental-vm-modules --test scripts/test_browser_message_streams.mjs
 * Additive follow-up to asupersync-b35gbf.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { getEventListeners } from "node:events";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";
import { BroadcastChannel, MessageChannel } from "node:worker_threads";

const sdkPath = process.env.ASUPERSYNC_BROWSER_SDK_SOURCE
  ?? fileURLToPath(new URL("../packages/browser/src/index.ts", import.meta.url));
const source = readFileSync(sdkPath, "utf8");
const javascript = stripTypeScriptTypes(source, { mode: "transform" });
console.log(JSON.stringify({
  scenario_id: "browser-message-streams",
  sdk_source_sha256: createHash("sha256").update(source).digest("hex"),
  evidence_scope: "actual SDK and Node native MessageChannel/BroadcastChannel; explicit raw-ABI double for owned lifecycle faults",
  no_claim: ["browser-engine execution", "Rust executor", "packaged WASM"],
}));

async function sdk(abi = {}) {
  const context = createContext({
    AbortController, ArrayBuffer, DataView, Uint8Array, URL, TextEncoder, TextDecoder,
    ReadableStream, WritableStream, WebAssembly, Error, TypeError, RangeError,
    DOMException, structuredClone, queueMicrotask, setTimeout, clearTimeout,
    MessageChannel, BroadcastChannel, window: {}, document: {}, isSecureContext: true,
    fetch() { throw new Error("unexpected fetch"); },
  });
  const modules = new Map();
  for (const [name, path, typescript] of [
    ["@asupersync/browser-core", "../packages/browser-core/index.js", false],
    ["./fetch.js", "../packages/browser/src/fetch.ts", true],
    ["@asupersync/browser-core/webtransport-streams", "../packages/browser-core/webtransport-streams.js", false],
  ]) {
    const raw = readFileSync(new URL(path, import.meta.url), "utf8");
    modules.set(name, new SourceTextModule(
      typescript ? stripTypeScriptTypes(raw, { mode: "transform" }) : raw, { context },
    ));
  }
  modules.set("./webtransport-streams.js", modules.get("@asupersync/browser-core/webtransport-streams"));
  const names = ["default", "abi_fingerprint", "abi_version", "fetch_request",
    "runtime_close", "runtime_create", "scope_close", "scope_enter", "task_cancel",
    "task_join", "task_spawn", "websocket_cancel", "websocket_close", "websocket_open",
    "websocket_recv", "websocket_send"];
  modules.set("./asupersync.js", new SyntheticModule(names, function () {
    for (const name of names) this.setExport(name, abi[name] ?? (() => { throw new Error(`unexpected ABI call: ${name}`); }));
  }, { context }));
  const module = new SourceTextModule(javascript, { context, identifier: sdkPath });
  await module.link((specifier) => {
    assert.ok(modules.has(specifier), `unhandled import ${specifier}`);
    return modules.get(specifier);
  });
  await module.evaluate();
  return module.namespace;
}

const authority = { capability: { capabilityGranted: true } };
const observe = (promise) => promise.then(
  (value) => ({ ok: true, value }), (error) => ({ ok: false, error }),
);
async function bounded(promise) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("message stream did not settle")), 2000);
    })]);
  } finally { clearTimeout(timer); }
}
function failed(result, reason) {
  assert.equal(result.ok, false);
  assert.equal(result.error.code, "ASUPERSYNC_BROWSER_MESSAGE_STREAM_FAILED");
  assert.equal(result.error.reason, reason);
  return result.error;
}
function throwsReason(operation, reason) {
  assert.throws(operation, (error) => {
    assert.equal(error.code, "ASUPERSYNC_BROWSER_MESSAGE_STREAM_FAILED");
    assert.equal(error.reason, reason);
    return true;
  });
}
function nativeDelivery(port, count) {
  return new Promise((resolve) => {
    let seen = 0;
    const listener = () => {
      if (++seen === count) {
        port.removeEventListener("message", listener);
        resolve();
      }
    };
    port.addEventListener("message", listener);
  });
}
function noListeners(port) {
  for (const type of ["message", "messageerror", "close"]) {
    assert.equal(getEventListeners(port, type).length, 0, `${type} hook retired`);
  }
}

// Fault injection below uses an explicit raw-ABI ledger double. Positive
// packaged-WASM integration lives in test_browser_message_regions_wasm.mjs.
async function ownedFixture(t, options = {}) {
  const calls = { spawn: [], cancel: [], join: [], scopeClose: [] };
  const tasks = new Map();
  const unit = '{"outcome":"ok","value":{"kind":"unit"}}';
  const refusal = (message) => JSON.stringify({ outcome: "err", failure: {
    code: "compatibility_rejected", recoverability: "transient", message,
  } });
  let nextRegion = 1, nextTask = 1;
  const api = await sdk({
    abi_version: () => JSON.stringify({ major: 1, minor: 0 }),
    abi_fingerprint: () => 1n,
    runtime_create: () => JSON.stringify({ kind: "runtime", slot: 0, generation: 1, owner_token: "17" }),
    scope_enter: () => JSON.stringify({ kind: "region", slot: nextRegion++, generation: 1, owner_token: "17" }),
    runtime_close: () => tasks.size === 0 ? unit : refusal("active task"),
    scope_close: (encoded) => {
      const handle = JSON.parse(encoded);
      calls.scopeClose.push(handle);
      if (options.acceptOwnerClose) {
        for (const [slot, state] of tasks) if (state.scope === handle.slot) tasks.delete(slot);
        return unit;
      }
      return [...tasks.values()].some((state) => state.scope === handle.slot) ? refusal("active task") : unit;
    },
    task_spawn: (encoded) => {
      const request = JSON.parse(encoded);
      const handle = { kind: "task", slot: nextTask++, generation: 1, owner_token: "17" };
      calls.spawn.push(request);
      tasks.set(handle.slot, { scope: request.scope.slot, phase: "active" });
      options.afterSpawn?.();
      return JSON.stringify(handle);
    },
    task_cancel: (encoded) => {
      const request = JSON.parse(encoded);
      calls.cancel.push(request);
      if (options.refuseCancel) return refusal("controlled cancellation refusal");
      const state = tasks.get(request.task.slot);
      if (!state || state.phase !== "active") return refusal("cancellation was repeated or task was retired");
      state.phase = "cancelling";
      return unit;
    },
    task_join: (handleJson, outcomeJson) => {
      const handle = JSON.parse(handleJson), outcome = JSON.parse(outcomeJson);
      calls.join.push({ handle, outcome });
      options.onJoin?.();
      if (options.refuseJoin) return refusal("controlled terminal publication refusal");
      assert.ok(tasks.delete(handle.slot), "one terminal publication releases one task");
      return outcomeJson;
    },
  });
  const unwrap = (outcome) => { assert.equal(outcome.outcome, "ok"); return outcome.value; };
  const runtime = new api.BrowserRuntime(unwrap(api.runtimeCreate()));
  const scope = unwrap(runtime.enterScope("controlled-message-owner"));
  const raw = new MessageChannel();
  const port = api.createBrowserMessagePort(raw.port2, { ...authority, start: false });
  t.after(async () => {
    options.refuseCancel = false;
    options.refuseJoin = false;
    options.afterSpawn = undefined;
    options.onJoin = undefined;
    try { await runtime.closeAsync(); }
    finally { raw.port1.close(); raw.port2.close(); }
  });
  return { api, runtime, scope, raw, port, calls, tasks, unwrap, options };
}

test("message streams preserve the default legacy callback and polling behavior", async () => {
  const api = await sdk();
  const raw = new MessageChannel();
  const port = api.createBrowserMessagePort(raw.port2, authority);
  const callbacks = [];
  port.onMessage((message) => callbacks.push(message));
  try {
    const delivered = nativeDelivery(raw.port2, 3);
    for (const value of [null, 0, "legacy"]) raw.port1.postMessage(value);
    await bounded(delivered);
    assert.deepEqual(callbacks, [null, 0, "legacy"]);
    assert.deepEqual(Array.from(port.takeMessages()), callbacks);
    assert.equal(port.takeMessages().length, 0);
  } finally { port.close(); raw.port1.close(); }
});

test("message streams validate capacity and pre-abort before taking ownership", async () => {
  const api = await sdk();
  const raw = new MessageChannel();
  const port = api.createBrowserMessagePort(raw.port2, authority);
  try {
    for (const capacity of [0, -1, 1.5, NaN, Infinity, 65_537]) {
      assert.throws(() => port.receiveStream({ maxQueuedMessages: capacity }), RangeError);
    }
    const abort = new AbortController();
    abort.abort();
    throwsReason(() => port.receiveStream({ signal: abort.signal }), "aborted");
    assert.equal(port.state, "open");
    assert.equal(getEventListeners(raw.port2, "close").length, 0);
    const receiver = port.receiveStream({ maxQueuedMessages: 65_536 });
    assert.equal(receiver.maxQueuedMessages, 65_536);
    await receiver.return();
    await receiver.closed;
  } finally { port.close(); raw.port1.close(); }
});

test("exclusive ownership refuses callbacks, legacy backlog, competing receivers and detach", async () => {
  const api = await sdk();
  const raw = new MessageChannel();
  const port = api.createBrowserMessagePort(raw.port2, authority);
  try {
    const unsubscribe = port.onMessage(() => {});
    throwsReason(() => port.receiveStream(), "message_callback_registered");
    unsubscribe();
    const delivered = nativeDelivery(raw.port2, 1);
    raw.port1.postMessage("pending");
    await bounded(delivered);
    throwsReason(() => port.receiveStream(), "legacy_messages_pending");
    assert.deepEqual(Array.from(port.takeMessages()), ["pending"]);
    const receiver = port.receiveStream();
    assert.equal(receiver.maxQueuedMessages, 64);
    for (const operation of [
      () => port.receiveStream(), () => port.takeMessages(), () => port.onMessage(() => {}),
      () => port.onMessageError(() => {}), () => port.detach(),
    ]) throwsReason(operation, "receiver_in_use");
    await receiver.return();
    noListeners(raw.port2);
  } finally { port.close(); raw.port1.close(); }
});

test("stream admission requires endpoint close and paired listener removal", async () => {
  const api = await sdk();
  for (const missing of ["close", "removeEventListener"]) {
    const raw = new MessageChannel();
    const original = raw.port2[missing].bind(raw.port2);
    raw.port2[missing] = undefined;
    const port = api.createBrowserMessagePort(raw.port2, authority);
    try {
      assert.throws(() => port.receiveStream(), TypeError);
      assert.equal(port.state, "open");
      assert.equal(getEventListeners(raw.port2, "close").length, 0);
      raw.port2[missing] = original;
      const receiver = port.receiveStream();
      await receiver.return();
      await receiver.closed;
      noListeners(raw.port2);
    } finally { raw.port2[missing] = original; port.close(); raw.port1.close(); }
  }
});

test("native endpoint aliases cannot bypass exclusive SDK receive ownership", async () => {
  const api = await sdk();
  const raw = new MessageChannel();
  const first = api.createBrowserMessagePort(raw.port2, authority);
  const second = api.createBrowserMessagePort(raw.port2, authority);
  try {
    assert.equal(getEventListeners(raw.port2, "message").length, 2, "legacy wrappers still coexist");
    throwsReason(() => first.receiveStream(), "receiver_in_use");
    assert.equal(second.detach(), raw.port2);
    const receiver = first.receiveStream();
    throwsReason(() => api.createBrowserMessagePort(raw.port2, authority), "receiver_in_use");
    assert.equal(getEventListeners(raw.port2, "message").length, 1, "no legacy mirror can be installed");
    const next = receiver.next();
    raw.port1.postMessage(7);
    assert.equal((await bounded(next)).value, 7);
    await receiver.return();
    noListeners(raw.port2);
    const afterClose = api.createBrowserMessagePort(raw.port2, authority);
    afterClose.close();
    noListeners(raw.port2);
  } finally { first.close(); raw.port1.close(); }
});

test("failed native port construction removes partial hooks and permits a clean retry", async () => {
  const api = await sdk();
  for (const failure of ["messageerror", "start"]) {
    const raw = new MessageChannel();
    const add = raw.port2.addEventListener.bind(raw.port2);
    const start = raw.port2.start.bind(raw.port2);
    const originalFailure = new Error(`native ${failure} setup failed`);
    raw.port2.addEventListener = (type, listener, options) => {
      add(type, listener, options);
      if (failure === type) throw originalFailure;
    };
    raw.port2.start = () => {
      if (failure === "start") throw originalFailure;
      start();
    };
    try {
      assert.throws(() => api.createBrowserMessagePort(raw.port2, authority), (error) => error === originalFailure);
      noListeners(raw.port2);
      raw.port2.addEventListener = add;
      raw.port2.start = start;
      const port = api.createBrowserMessagePort(raw.port2, authority);
      const receiver = port.receiveStream();
      const next = receiver.next();
      raw.port1.postMessage("still open");
      assert.equal((await bounded(next)).value, "still open");
      await receiver.return();
      noListeners(raw.port2);
    } finally { raw.port2.addEventListener = add; raw.port2.start = start; raw.port1.close(); raw.port2.close(); }
  }
});

test("a pending receive handles native transfer ownership and permits only one waiter", async () => {
  const api = await sdk();
  const raw = new MessageChannel();
  const port = api.createBrowserMessagePort(raw.port2, { ...authority, start: false });
  const receiver = port.receiveStream({ maxQueuedMessages: 1 });
  try {
    const first = receiver.next();
    failed(await observe(receiver.next()), "receive_in_progress");
    const bytes = Uint8Array.of(7, 8, 9);
    raw.port1.postMessage(bytes, [bytes.buffer]);
    assert.equal(bytes.byteLength, 0, "the real host transferred the sender buffer");
    const read = await bounded(first);
    assert.equal(read.done, false);
    assert.deepEqual(Array.from(read.value), [7, 8, 9]);
    assert.equal(receiver.queuedMessages, 0);
    assert.equal(receiver.state, "open");
  } finally { await receiver.return(); raw.port1.close(); }
});

test("queued receives are FIFO and release each SDK queue credit", async () => {
  const api = await sdk();
  const raw = new MessageChannel();
  const port = api.createBrowserMessagePort(raw.port2, authority);
  const receiver = port.receiveStream({ maxQueuedMessages: 3 });
  try {
    const delivered = nativeDelivery(raw.port2, 3);
    for (const value of [1, 2, 3]) raw.port1.postMessage(value);
    await bounded(delivered);
    assert.equal(receiver.queuedMessages, 3);
    for (const value of [1, 2, 3]) {
      assert.equal((await receiver.next()).value, value);
      assert.equal(receiver.queuedMessages, 3 - value);
    }
    const next = receiver.next();
    raw.port1.postMessage(4);
    assert.equal((await bounded(next)).value, 4);
  } finally { await receiver.return(); raw.port1.close(); }
});

test("partially drained large queues preserve FIFO while reusing capacity", async () => {
  const api = await sdk();
  const raw = new MessageChannel();
  const port = api.createBrowserMessagePort(raw.port2, authority);
  const receiver = port.receiveStream({ maxQueuedMessages: 2048 });
  try {
    let delivered = nativeDelivery(raw.port2, 2048);
    for (let value = 0; value < 2048; value += 1) raw.port1.postMessage(value);
    await bounded(delivered);
    for (let value = 0; value < 1500; value += 1) assert.equal((await receiver.next()).value, value);
    assert.equal(receiver.queuedMessages, 548);
    delivered = nativeDelivery(raw.port2, 1500);
    for (let value = 2048; value < 3548; value += 1) raw.port1.postMessage(value);
    await bounded(delivered);
    assert.equal(receiver.queuedMessages, 2048);
    for (let value = 1500; value < 3548; value += 1) assert.equal((await receiver.next()).value, value);
    assert.equal(receiver.queuedMessages, 0);
  } finally { await receiver.return(); raw.port1.close(); }
});

test("overflow fails closed without an unbounded legacy mirror or stale queue", async () => {
  const api = await sdk();
  const raw = new MessageChannel();
  const port = api.createBrowserMessagePort(raw.port2, authority);
  const receiver = port.receiveStream({ maxQueuedMessages: 2 });
  try {
    const closed = observe(receiver.closed);
    for (const value of [1, 2, 3]) raw.port1.postMessage(value);
    const failure = failed(await bounded(closed), "message_limit_exceeded");
    assert.equal(receiver.state, "errored");
    assert.equal(receiver.queuedMessages, 0);
    assert.equal(port.state, "closed");
    assert.equal(failed(await observe(receiver.next()), "message_limit_exceeded"), failure);
    throwsReason(() => port.takeMessages(), "receiver_in_use");
    noListeners(raw.port2);
  } finally { raw.port1.close(); port.close(); }
});

test("AbortSignal cancels a genuinely pending receive and removes all hooks", async () => {
  const api = await sdk();
  const raw = new MessageChannel();
  const port = api.createBrowserMessagePort(raw.port2, authority);
  const abort = new AbortController();
  const receiver = port.receiveStream({ signal: abort.signal });
  try {
    const pending = observe(receiver.next());
    assert.equal(getEventListeners(abort.signal, "abort").length, 1);
    abort.abort("private caller detail");
    failed(await bounded(pending), "aborted");
    failed(await observe(receiver.closed), "aborted");
    assert.equal(receiver.state, "cancelled");
    assert.equal(receiver.queuedMessages, 0);
    assert.equal(getEventListeners(abort.signal, "abort").length, 0);
    noListeners(raw.port2);
    await receiver.cancel();
  } finally { raw.port1.close(); port.close(); }
});

test("return, source close and source abort settle a pending receive exactly once", async () => {
  const api = await sdk();
  for (const action of ["return", "close", "abort"]) {
    const raw = new MessageChannel();
    const nativeClose = raw.port2.close.bind(raw.port2);
    let closes = 0;
    raw.port2.close = () => { closes += 1; nativeClose(); };
    const port = api.createBrowserMessagePort(raw.port2, authority);
    const receiver = port.receiveStream();
    let settlements = 0;
    const pending = observe(receiver.next()).then((result) => { settlements += 1; return result; });
    try {
      if (action === "return") await receiver.return();
      else port[action]();
      const read = await bounded(pending);
      if (action === "abort") failed(read, "aborted");
      else { assert.equal(read.ok, true); assert.equal(read.value.done, true); }
      await receiver.return();
      assert.equal(settlements, 1);
      assert.equal(closes, 1, "exclusive cleanup closes the actual endpoint once");
      noListeners(raw.port2);
    } finally { raw.port1.close(); }
  }
});

test("native peer MessagePort close ends a pending receiver without polling", async () => {
  const api = await sdk();
  const raw = new MessageChannel();
  const port = api.createBrowserMessagePort(raw.port2, authority);
  const receiver = port.receiveStream();
  const pending = receiver.next();
  raw.port1.close();
  try {
    assert.equal((await bounded(pending)).done, true);
    await receiver.closed;
    assert.equal(port.state, "closed");
    noListeners(raw.port2);
  } finally { port.close(); }
});

test("owned close attempts every hook and host close after listener removal throws", async () => {
  const api = await sdk();
  const raw = new MessageChannel();
  const remove = raw.port2.removeEventListener.bind(raw.port2);
  const nativeClose = raw.port2.close.bind(raw.port2);
  const attempted = [];
  raw.port2.removeEventListener = (type, listener, options) => {
    attempted.push(type);
    if (type === "message") throw new Error("host refuses listener retirement");
    remove(type, listener, options);
  };
  raw.port2.close = () => { attempted.push("host_close"); nativeClose(); };
  const port = api.createBrowserMessagePort(raw.port2, authority);
  const receiver = port.receiveStream();
  try {
    const pending = observe(receiver.next());
    throwsReason(() => port.close(), "cleanup_failed");
    failed(await bounded(pending), "cleanup_failed");
    failed(await observe(receiver.closed), "cleanup_failed");
    assert.equal(receiver.state, "errored");
    assert.equal(receiver.queuedMessages, 0);
    assert.deepEqual(attempted, ["message", "messageerror", "close", "host_close"]);
    assert.equal(getEventListeners(raw.port2, "messageerror").length, 0);
    assert.equal(getEventListeners(raw.port2, "close").length, 0);
    failed(await observe(receiver.return()), "cleanup_failed");
  } finally {
    for (const listener of getEventListeners(raw.port2, "message")) remove("message", listener);
    nativeClose();
    raw.port1.close();
  }
});

test("async iteration break closes the endpoint and clears retained messages", async () => {
  const api = await sdk();
  const raw = new MessageChannel();
  const port = api.createBrowserMessagePort(raw.port2, authority);
  const receiver = port.receiveStream({ maxQueuedMessages: 2 });
  try {
    const delivered = nativeDelivery(raw.port2, 2);
    raw.port1.postMessage(1);
    raw.port1.postMessage(2);
    await bounded(delivered);
    for await (const value of receiver) { assert.equal(value, 1); break; }
    await receiver.closed;
    assert.equal(receiver.queuedMessages, 0);
    assert.equal(port.state, "closed");
    noListeners(raw.port2);
  } finally { raw.port1.close(); port.close(); }
});

test("native messageerror rejects receives with stable payload-free diagnostics", async () => {
  const api = await sdk();
  const raw = new MessageChannel();
  const port = api.createBrowserMessagePort(raw.port2, authority);
  const receiver = port.receiveStream();
  try {
    const pending = observe(receiver.next());
    raw.port2.dispatchEvent(new Event("messageerror"));
    failed(await bounded(pending), "messageerror");
    failed(await observe(receiver.closed), "messageerror");
    assert.equal(receiver.state, "errored");
    assert.equal(port.state, "errored");
    noListeners(raw.port2);
  } finally { raw.port1.close(); port.close(); }
});

test("BroadcastChannel streams deliver native messages and keep sender self-exclusion", async () => {
  const api = await sdk();
  const name = `asupersync-message-stream-${process.pid}-delivery`;
  const sender = api.createBrowserBroadcastChannel(name, authority);
  const channel = api.createBrowserBroadcastChannel(name, authority);
  const receiver = channel.receiveStream({ maxQueuedMessages: 2 });
  try {
    const first = receiver.next();
    sender.post({ command: "work", sequence: 1 });
    const read = await bounded(first);
    assert.equal(read.value.command, "work");
    assert.equal(read.value.sequence, 1);
    assert.equal(sender.takeMessages().length, 0);
    const second = receiver.next();
    sender.post(Uint8Array.of(3, 4));
    assert.deepEqual(Array.from((await bounded(second)).value), [3, 4]);
    await receiver.return();
    await receiver.closed;
    assert.equal(channel.state, "closed");
  } finally { sender.close(); channel.close(); }
});

test("BroadcastChannel overflow and abort release exclusive receive ownership", async () => {
  const api = await sdk();
  for (const action of ["overflow", "abort"]) {
    const name = `asupersync-message-stream-${process.pid}-${action}`;
    const sender = api.createBrowserBroadcastChannel(name, authority);
    const channel = api.createBrowserBroadcastChannel(name, authority);
    const receiver = channel.receiveStream({ maxQueuedMessages: 1 });
    try {
      const closed = observe(receiver.closed);
      if (action === "overflow") { sender.post(1); sender.post(2); }
      else channel.abort("stop");
      failed(await bounded(closed), action === "overflow" ? "message_limit_exceeded" : "aborted");
      assert.equal(receiver.queuedMessages, 0);
      throwsReason(() => channel.takeMessages(), "receiver_in_use");
    } finally { sender.close(); channel.close(); }
  }
});

test("BroadcastChannel raw aliases cannot install a legacy inbox after stream admission", async () => {
  const api = await sdk();
  const raw = new BroadcastChannel(`asupersync-message-stream-${process.pid}-alias`);
  const support = api.detectBrowserNativeMessagingSupport("broadcast_channel", authority);
  const channel = new api.BrowserBroadcastChannel(raw, support);
  try {
    const receiver = channel.receiveStream();
    throwsReason(() => new api.BrowserBroadcastChannel(raw, support), "receiver_in_use");
    assert.equal(getEventListeners(raw, "message").length, 1);
    await receiver.return();
    assert.equal(getEventListeners(raw, "message").length, 0);
    assert.equal(getEventListeners(raw, "messageerror").length, 0);
    const afterClose = new api.BrowserBroadcastChannel(raw, support);
    afterClose.close();
  } finally { channel.close(); raw.close(); }
});

test("failed BroadcastChannel construction rolls back hooks without closing the borrowed channel", async () => {
  const api = await sdk();
  const name = `asupersync-message-stream-${process.pid}-constructor`;
  const raw = new BroadcastChannel(name);
  const sender = new BroadcastChannel(name);
  const support = api.detectBrowserNativeMessagingSupport("broadcast_channel", authority);
  const add = raw.addEventListener.bind(raw);
  const originalFailure = new Error("native broadcast setup failed");
  raw.addEventListener = (type, listener, options) => {
    add(type, listener, options);
    if (type === "messageerror") throw originalFailure;
  };
  try {
    assert.throws(() => new api.BrowserBroadcastChannel(raw, support), (error) => error === originalFailure);
    assert.equal(getEventListeners(raw, "message").length, 0);
    assert.equal(getEventListeners(raw, "messageerror").length, 0);
    raw.addEventListener = add;
    const channel = new api.BrowserBroadcastChannel(raw, support);
    const receiver = channel.receiveStream();
    const next = receiver.next();
    sender.postMessage("still open");
    assert.equal((await bounded(next)).value, "still open");
    await receiver.return();
  } finally { raw.addEventListener = add; raw.close(); sender.close(); }
});

test("owned return retains an ABI-refused terminal for explicit owner-close retry", async (t) => {
  const f = await ownedFixture(t, { refuseJoin: true });
  const receiver = f.unwrap(f.scope.receiveMessages(f.port));
  const next = observe(receiver.next());
  failed(await bounded(observe(receiver.return())), "terminal_publication_failed");
  failed(await bounded(next), "terminal_publication_failed");
  failed(await bounded(observe(receiver.closed)), "terminal_publication_failed");
  noListeners(f.raw.port2);
  assert.equal(f.scope.close().outcome, "err", "ABI task remains admitted");
  assert.equal(f.tasks.size, 1);
  assert.equal(f.calls.cancel.length, 0, "normal return does not cancel");
  f.options.refuseJoin = false;
  f.unwrap(await bounded(f.scope.closeAsync()));
  assert.equal(f.tasks.size, 0);
  assert.equal(f.calls.join.length, 2);
  assert.deepEqual(f.calls.join[0], f.calls.join[1], "retry publishes the original terminal");
});

test("owned cancellation retry does not repeat accepted ABI cancellation or mutable public errors", async (t) => {
  const f = await ownedFixture(t, { refuseJoin: true });
  const receiver = f.unwrap(f.scope.receiveMessages(f.port));
  const next = observe(receiver.next());
  assert.equal((await bounded(f.scope.closeAsync())).outcome, "err");
  const error = failed(await bounded(next), "terminal_publication_failed");
  error.reason = "messageerror";
  error.message = "consumer mutation must not become the task result";
  assert.equal(f.calls.cancel.length, 1);
  assert.equal(f.calls.join.length, 1);
  f.options.refuseJoin = false;
  f.unwrap(await bounded(f.scope.closeAsync()));
  assert.equal(f.calls.cancel.length, 1, "Cancelling is not Active on retry");
  assert.equal(f.calls.join.length, 2);
  assert.deepEqual(f.calls.join[0], f.calls.join[1]);
  assert.equal(f.calls.join[1].outcome.outcome, "cancelled");
  assert.equal(f.calls.join[1].outcome.cancellation.kind, "scope_close");
});

test("owned cancellation refusal closes the native source and retains the task until retry", async (t) => {
  const f = await ownedFixture(t, { refuseCancel: true });
  const receiver = f.unwrap(f.scope.receiveMessages(f.port));
  const next = observe(receiver.next());
  assert.equal((await bounded(f.scope.closeAsync())).outcome, "err");
  failed(await bounded(next), "terminal_publication_failed");
  noListeners(f.raw.port2);
  assert.equal(f.calls.cancel.length, 1);
  assert.equal(f.calls.join.length, 0);
  assert.equal(f.tasks.size, 1);
  f.options.refuseCancel = false;
  f.unwrap(await bounded(f.scope.closeAsync()));
  assert.equal(f.calls.cancel.length, 2);
  assert.equal(f.calls.join.length, 1);
  assert.equal(f.tasks.size, 0);
});

test("owned failed hook cleanup retains credit and retries only incomplete native operations", async (t) => {
  const f = await ownedFixture(t);
  const remove = f.raw.port2.removeEventListener.bind(f.raw.port2);
  const close = f.raw.port2.close.bind(f.raw.port2);
  let rejectRemoval = true, closes = 0;
  const removals = [];
  f.raw.port2.removeEventListener = (type, listener) => {
    removals.push(type);
    if (type === "message" && rejectRemoval) throw new Error("controlled hook refusal");
    remove(type, listener);
  };
  f.raw.port2.close = () => { closes++; close(); };
  const receiver = f.unwrap(f.scope.receiveMessages(f.port));
  const next = observe(receiver.next());
  try {
    assert.equal((await bounded(f.scope.closeAsync())).outcome, "err");
    failed(await bounded(next), "cleanup_failed");
    assert.equal(f.calls.cancel.length, 0);
    assert.equal(f.calls.join.length, 0);
    assert.equal(f.tasks.size, 1);
    assert.equal(closes, 1, "all independent native cleanup was attempted");
    throwsReason(() => f.api.createBrowserMessagePort(f.raw.port2, authority), "receiver_in_use");
    rejectRemoval = false;
    f.unwrap(await bounded(f.scope.closeAsync()));
    assert.equal(f.tasks.size, 0);
    assert.equal(closes, 1, "successful native close is not repeated");
    assert.deepEqual(removals, ["message", "messageerror", "close", "message"]);
    noListeners(f.raw.port2);
    const aliasAfterRelease = f.api.createBrowserMessagePort(f.raw.port2, authority);
    aliasAfterRelease.close();
  } finally { rejectRemoval = false; f.raw.port2.removeEventListener = remove; }
});

test("owned terminal reads reentered from native cleanup wait for publication refusal", async (t) => {
  const f = await ownedFixture(t, { refuseJoin: true });
  const close = f.raw.port2.close.bind(f.raw.port2);
  let receiver, reenteredNext, reenteredReturn;
  f.raw.port2.close = () => {
    reenteredNext = observe(receiver.next());
    reenteredReturn = observe(receiver.return());
    close();
  };
  receiver = f.unwrap(f.scope.receiveMessages(f.port));
  failed(await bounded(observe(receiver.return())), "terminal_publication_failed");
  failed(await bounded(reenteredNext), "terminal_publication_failed");
  failed(await bounded(reenteredReturn), "terminal_publication_failed");
  assert.equal(f.calls.join.length, 1);
  f.options.refuseJoin = false;
  f.unwrap(await bounded(f.scope.closeAsync()));
  assert.equal(f.calls.join.length, 2);
});

test("external source close fences reentrant completion until a late native close failure is known", async (t) => {
  for (const surface of ["message_port", "broadcast_channel"]) {
    const f = await ownedFixture(t);
    const raw = surface === "message_port" ? f.raw.port2
      : new BroadcastChannel(`asupersync-message-stream-${process.pid}-external-close`);
    const source = surface === "message_port" ? f.port : new f.api.BrowserBroadcastChannel(
      raw, f.api.detectBrowserNativeMessagingSupport("broadcast_channel", authority),
    );
    const close = raw.close.bind(raw);
    let rejectClose = true, receiver, reenteredNext, reenteredReturn;
    raw.close = () => {
      if (rejectClose) {
        reenteredNext = observe(receiver.next());
        reenteredReturn = observe(receiver.return());
        throw new Error("native close failed after reentrant completion");
      }
      close();
    };
    receiver = f.unwrap(f.scope.receiveMessages(source));
    const pending = observe(receiver.next());
    try {
      throwsReason(() => source.close(), "cleanup_failed");
      failed(await bounded(pending), "cleanup_failed");
      failed(await bounded(reenteredNext), "cleanup_failed");
      failed(await bounded(reenteredReturn), "cleanup_failed");
      assert.equal(f.calls.join.length, 0, "failed native cleanup cannot release the task");
      assert.equal(f.tasks.size, 1);
      rejectClose = false;
      f.unwrap(await bounded(f.scope.closeAsync()));
      assert.equal(f.calls.join.length, 1);
      assert.equal(f.tasks.size, 0);
      assert.equal(f.calls.join[0].outcome.outcome, "err");
    } finally { rejectClose = false; close(); }
  }
});

test("owned cleanup retains missing close/removal capabilities until the host restores them", async (t) => {
  for (const surface of ["message_port", "broadcast_channel"]) {
    for (const missing of ["close", "removeEventListener"]) {
      const f = await ownedFixture(t);
      const raw = surface === "message_port" ? f.raw.port2 : new BroadcastChannel(
        `asupersync-message-stream-${process.pid}-missing-${missing}`,
      );
      const close = raw.close.bind(raw);
      const original = raw[missing].bind(raw);
      const source = surface === "message_port" ? f.port : new f.api.BrowserBroadcastChannel(
        raw, f.api.detectBrowserNativeMessagingSupport("broadcast_channel", authority),
      );
      const receiver = f.unwrap(f.scope.receiveMessages(source));
      raw[missing] = undefined;
      try {
        failed(await bounded(observe(receiver.return())), "cleanup_failed");
        assert.equal(f.calls.join.length, 0);
        assert.equal(f.tasks.size, 1);
        raw[missing] = original;
        f.unwrap(await bounded(f.scope.closeAsync()));
        assert.equal(f.calls.join.length, 1);
        assert.equal(f.tasks.size, 0);
        for (const type of ["message", "messageerror"]) assert.equal(getEventListeners(raw, type).length, 0);
      } finally { raw[missing] = original; close(); }
    }
  }
});

test("owned admission unwinds a taskSpawn reentrant async close before touching the source", async (t) => {
  const f = await ownedFixture(t);
  let closing;
  f.options.afterSpawn = () => { closing = f.scope.closeAsync(); };
  const result = f.scope.receiveMessages(f.port);
  assert.equal(result.outcome, "err");
  assert.equal(result.failure.recoverability, "transient");
  f.unwrap(await bounded(closing));
  assert.equal(f.tasks.size, 0);
  assert.equal(f.port.state, "open");
  assert.equal(getEventListeners(f.raw.port2, "close").length, 0);
  const receiver = f.port.receiveStream();
  const next = receiver.next();
  f.raw.port1.postMessage("still available");
  assert.equal((await bounded(next)).value, "still available");
  await receiver.return();
});

test("accepted synchronous owner close during a native capability getter cannot orphan a receiver", async (t) => {
  const f = await ownedFixture(t, { acceptOwnerClose: true });
  const close = f.raw.port2.close.bind(f.raw.port2);
  let closed = false;
  Object.defineProperty(f.raw.port2, "close", { configurable: true, get() {
    if (!closed && f.calls.spawn.length !== 0) {
      closed = true;
      f.unwrap(f.scope.close());
    }
    return close;
  } });
  const result = f.scope.receiveMessages(f.port);
  assert.equal(result.outcome, "err");
  assert.equal(closed, true);
  assert.equal(f.port.state, "open");
  assert.equal(getEventListeners(f.raw.port2, "close").length, 0);
  assert.equal(f.calls.join.length, 0, "accepted owner barrier already released the provisional task");
  const receiver = f.port.receiveStream();
  await receiver.return();
});

test("accepted synchronous owner close during native start closes the activated receiver before exposure", async (t) => {
  const f = await ownedFixture(t, { acceptOwnerClose: true });
  const start = f.raw.port2.start.bind(f.raw.port2);
  f.raw.port2.start = () => { f.unwrap(f.scope.close()); start(); };
  const receiver = f.unwrap(f.scope.receiveMessages(f.port));
  assert.equal(receiver.state, "cancelled");
  failed(await bounded(observe(receiver.next())), "aborted");
  failed(await bounded(observe(receiver.closed)), "aborted");
  noListeners(f.raw.port2);
  assert.equal(f.tasks.size, 0);
  assert.equal(f.calls.join.length, 0);
});

test("untracked core-created regions refuse native receive ownership before task admission", async (t) => {
  const f = await ownedFixture(t);
  const core = f.unwrap(f.api.scopeEnter({ parent: f.runtime.core }));
  const untracked = new f.api.RegionHandle(core);
  assert.equal(untracked.receiveMessages(f.port).outcome, "err");
  const nested = f.unwrap(untracked.enterScope("still-untracked-from-runtime"));
  assert.equal(nested.receiveMessages(f.port).outcome, "err");
  assert.equal(f.calls.spawn.length, 0);
  assert.equal(f.port.state, "open");
  const receiver = f.port.receiveStream();
  await receiver.return();
});

test("host-thrown objects with hostile error accessors cannot strand an admitted receiver task", async (t) => {
  for (const kind of ["accessor", "proxy"]) {
    const f = await ownedFixture(t);
    const close = f.raw.port2.close.bind(f.raw.port2);
    const poison = kind === "accessor"
      ? Object.defineProperty({}, "code", { get() { throw new Error("error code getter failed"); } })
      : new Proxy({}, { has() { throw new Error("error property trap failed"); } });
    let thrown = false;
    Object.defineProperty(f.raw.port2, "close", { configurable: true, get() {
      if (!thrown && f.calls.spawn.length !== 0) { thrown = true; throw poison; }
      return close;
    } });
    assert.equal(f.scope.receiveMessages(f.port).outcome, "err");
    assert.equal(thrown, true);
    assert.equal(f.tasks.size, 0);
    assert.equal(f.calls.join.length, 1);
    assert.equal(f.port.state, "open");
    f.unwrap(await bounded(f.scope.closeAsync()));
    const receiver = f.port.receiveStream();
    await receiver.return();
  }
});
