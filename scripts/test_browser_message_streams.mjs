/**
 * Actual SDK receive streams over Node's native MessageChannel/BroadcastChannel.
 * Unrelated generated WASM exports are fail-fast substitutes: this proves the
 * JS/host boundary, not browser-engine or Rust-executor behavior.
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
  evidence_scope: "actual SDK and Node native MessageChannel/BroadcastChannel",
  no_claim: ["browser-engine execution", "Rust executor", "packaged WASM"],
}));

async function sdk() {
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
    for (const name of names) this.setExport(name, () => { throw new Error(`unexpected ABI call: ${name}`); });
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
