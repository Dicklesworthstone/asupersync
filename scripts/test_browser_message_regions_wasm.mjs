/**
 * Region-owned operations over actual SDK source, the checked-in WASM ABI,
 * and Node's native message, WebSocket, and WHATWG stream implementations.
 * This harness supplies browser-like globals for SDK admission; it is not a
 * browser-engine run, a Rust rebuild, or proof of Rust executor dispatch.
 * node --unhandled-rejections=strict --experimental-vm-modules --test scripts/test_browser_message_regions_wasm.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { getEventListeners } from "node:events";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { createContext, SourceTextModule, runInContext } from "node:vm";
import { BroadcastChannel, MessageChannel } from "node:worker_threads";

const files = [
  ["sdk", "packages/browser/src/index.ts", true],
  ["@asupersync/browser-core", "packages/browser-core/index.js", false],
  ["./fetch.js", "packages/browser/src/fetch.ts", true],
  ["./websocket.js", "packages/browser/src/websocket.ts", true],
  ["./stream-pipe.js", "packages/browser/src/stream-pipe.ts", true],
  ["./byte-pipe.js", "packages/browser/src/byte-pipe.ts", true],
  ["./asupersync.js", "packages/browser-core/asupersync.js", false],
  ["./webtransport-streams.js", "packages/browser-core/webtransport-streams.js", false],
];
const inputs = new Map();
const hashes = {};
for (const [, path] of files) {
  const bytes = readFileSync(new URL(`../${path}`, import.meta.url));
  inputs.set(path, bytes.toString());
  hashes[path] = createHash("sha256").update(bytes).digest("hex");
}
const wasmPath = "packages/browser-core/asupersync_bg.wasm";
const wasmBytes = readFileSync(new URL(`../${wasmPath}`, import.meta.url));
hashes[wasmPath] = createHash("sha256").update(wasmBytes).digest("hex");
console.log(JSON.stringify({
  scenario_id: "browser-message-regions-packaged-wasm",
  evidence_scope: "actual SDK, checked-in generated JS/WASM ABI, native Node message, WebSocket, and stream hosts",
  no_claim: ["browser-engine execution", "Rust rebuild", "Rust executor dispatch"],
  source_sha256: hashes,
}));

async function loadSdk(globals = {}) {
  const context = createContext({
    console, AbortController, AbortSignal, ArrayBuffer, DataView, Uint8Array, URL,
    EventTarget, MessageEvent, WebSocket,
    TextEncoder, TextDecoder, ReadableStream, WritableStream, WebAssembly,
    MessageChannel, BroadcastChannel, Response, Request, structuredClone,
    queueMicrotask, setTimeout, clearTimeout, window: {}, document: {},
    isSecureContext: true,
    ...globals,
  });
  const modules = new Map();
  for (const [name, path, typescript] of files) {
    const text = inputs.get(path);
    modules.set(name, new SourceTextModule(
      typescript ? stripTypeScriptTypes(text, { mode: "transform" }) : text,
      { context, identifier: fileURLToPath(new URL(`../${path}`, import.meta.url)) },
    ));
  }
  modules.set("@asupersync/browser-core/webtransport-streams", modules.get("./webtransport-streams.js"));
  const entry = modules.get("sdk");
  await entry.link((specifier) => {
    assert.ok(modules.has(specifier), `unexpected module import ${specifier}`);
    return modules.get(specifier);
  });
  await entry.evaluate();
  context.sdk = entry.namespace;
  context.wasmBytes = wasmBytes;
  // Build the initializer object in the module's own realm, as a browser would.
  await runInContext("sdk.init({ module_or_path: wasmBytes })", context);
  const raw = modules.get("./asupersync.js").namespace;
  return {
    sdk: entry.namespace,
    // Counts from the checked-in WASM handle ledger, not Rust task dispatch.
    snapshot: () => JSON.parse(raw.browser_operator_snapshot()),
  };
}

function ok(outcome) {
  assert.equal(outcome.outcome, "ok", JSON.stringify(outcome));
  return outcome.value;
}

const authority = { capability: { capabilityGranted: true } };
const observe = (promise) => promise.then(
  (value) => ({ ok: true, value }), (error) => ({ ok: false, error }),
);
function failed(result, reason) {
  assert.equal(result.ok, false);
  assert.equal(result.error.code, "ASUPERSYNC_BROWSER_MESSAGE_STREAM_FAILED");
  assert.equal(result.error.reason, reason);
}
async function bounded(promise) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("owned message operation did not settle")), 2000);
    })]);
  } finally { clearTimeout(timer); }
}
async function fixture(t, options = {}) {
  const { sdk, snapshot } = await loadSdk(options.globals);
  const runtime = ok(await sdk.createBrowserRuntime({ ...options.runtimeOptions, eagerInit: false }));
  const scope = ok(runtime.enterScope("message-receive-integration"));
  let runtimeClosed = false;
  const closeRuntime = async () => {
    if (runtimeClosed) return;
    ok(await bounded(runtime.closeAsync()));
    runtimeClosed = true;
  };
  t.after(closeRuntime);
  return { sdk, runtime, scope, closeRuntime, snapshot };
}
function channel(t, sdk) {
  const pair = sdk.createBrowserMessageChannel(authority);
  t.after(() => pair.close());
  return pair;
}

test("WASM WebSocket ownership waits for native peer close and retires its real ABI task", { timeout: 5000 }, async (t) => {
  let resolveConnected, resolveClosing, resolveDisconnected;
  const connected = new Promise(resolve => { resolveConnected = resolve; });
  const peerClosing = new Promise(resolve => { resolveClosing = resolve; });
  const disconnected = new Promise(resolve => { resolveDisconnected = resolve; });
  const server = createServer();
  let peerSocket;
  let input = Buffer.alloc(0);
  const received = [];
  const frame = (opcode, payload = Buffer.alloc(0)) => {
    assert.ok(payload.length < 126, "this independent peer only needs small frames");
    return Buffer.concat([Buffer.from([0x80 | opcode, payload.length]), payload]);
  };
  server.on("upgrade", (request, socket, head) => {
    peerSocket = socket;
    const accept = createHash("sha1")
      .update(`${request.headers["sec-websocket-key"]}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
      .digest("base64");
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    socket.on("close", resolveDisconnected);
    socket.on("error", () => {});
    const consume = chunk => {
      input = Buffer.concat([input, chunk]);
      while (input.length >= 2) {
        const length = input[1] & 127;
        assert.ok(length < 126, "client messages fit the independent small-frame parser");
        assert.ok(input[1] & 128, "native client frames are masked");
        if (input.length < 6 + length) return;
        const opcode = input[0] & 15;
        const payload = Buffer.from(input.subarray(6, 6 + length));
        for (let i = 0; i < payload.length; i += 1) payload[i] ^= input[2 + i % 4];
        input = input.subarray(6 + length);
        received.push({ opcode, payload });
        if (opcode === 8) resolveClosing(payload);
      }
    };
    socket.on("data", consume);
    if (head.length) consume(head);
    resolveConnected();
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  // Registered before the fixture's runtime cleanup so failure also releases
  // the real socket that an owned task could still be waiting to close.
  t.after(async () => {
    peerSocket?.destroy();
    await new Promise(resolve => server.close(resolve));
  });
  const { scope, closeRuntime, snapshot } = await fixture(t);
  assert.equal(snapshot().tasks.total, 0);
  const socket = new WebSocket(`ws://127.0.0.1:${server.address().port}`);
  const events = ["open", "message", "error", "close"];
  const listenerCounts = () => Object.fromEntries(events.map(type => [type, getEventListeners(socket, type).length]));
  const beforeListeners = listenerCounts();
  assert.deepEqual(beforeListeners, { open: 0, message: 0, error: 0, close: 0 });
  const handle = ok(scope.adoptWebSocket(socket, { maxQueuedMessages: 2, maxQueuedBytes: 64 }));
  assert.equal(snapshot().tasks.total, 1, "adoption admitted a real checked-in ABI task");
  ok(await bounded(handle.opened));
  await bounded(connected);
  ok(handle.send("owned-ledger-send"));
  const text = handle.receive();
  peerSocket.write(frame(1, Buffer.from("héllo through WASM ownership")));
  peerSocket.write(frame(2, Buffer.from([0, 255, 7])));
  assert.equal(ok(await bounded(text)).value, "héllo through WASM ownership");
  assert.deepEqual([...ok(await bounded(handle.receive())).value], [0, 255, 7]);

  const pendingRead = handle.receive();
  let ownerSettled = false;
  let terminalSettled = false;
  const closing = scope.closeAsync();
  void closing.then(() => { ownerSettled = true; });
  void handle.closed.then(() => { terminalSettled = true; });
  const closePayload = await bounded(peerClosing);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(socket.readyState, WebSocket.CLOSING);
  assert.equal(ownerSettled, false, "scope close cannot outrun the peer's close acknowledgement");
  assert.equal(terminalSettled, false, "task terminal is withheld until native close");
  assert.equal(snapshot().tasks.total, 1, "the live native close remains owned in the ABI ledger");
  assert.equal(received.find(message => message.opcode === 1).payload.toString(), "owned-ledger-send");

  peerSocket.end(frame(8, closePayload));
  ok(await bounded(closing));
  assert.equal((await bounded(pendingRead)).outcome, "cancelled");
  assert.equal((await bounded(handle.closed)).outcome, "cancelled");
  await bounded(disconnected);
  assert.equal(socket.readyState, WebSocket.CLOSED);
  assert.deepEqual(listenerCounts(), beforeListeners, "all owned native socket listeners retired");
  assert.equal(snapshot().tasks.total, 0, "successful owner close retains no ABI task");
  assert.equal(snapshot().tasks.cleanup_pending, 0);
  await closeRuntime();
  console.log(JSON.stringify({
    scenario_id: "browser-websocket-owned-packaged-wasm",
    received_messages: 2, sent_messages: 1,
    pending_owner_close_before_peer_ack: true,
    wasm_task_counts: [0, 1, 1, 0], native_listeners_after_close: listenerCounts(),
    evidence_scope: "actual SDK, checked-in JS/WASM handle ledger, native Node WebSocket and HTTP-upgrade peer",
    no_claim: ["browser-engine execution", "Rust rebuild", "Rust executor dispatch"],
  }));
});

test("WASM message ownership delivers native FIFO/transfer and retires on return", async (t) => {
  const { sdk, scope } = await fixture(t);
  const pair = channel(t, sdk);
  const stream = ok(scope.receiveMessages(pair.port2, { maxQueuedMessages: 2 }));
  const pending = stream.next();
  pair.port1.send({ order: 1 });
  const bytes = new Uint8Array([3, 5, 8]);
  pair.port1.send(bytes.buffer, [bytes.buffer]);
  assert.equal(bytes.byteLength, 0);
  assert.equal((await bounded(pending)).value.order, 1);
  assert.deepEqual([...new Uint8Array((await bounded(stream.next())).value)], [3, 5, 8]);
  assert.equal((await bounded(stream.return())).done, true);
  await bounded(stream.closed);
  assert.equal(stream.queuedMessages, 0);
  assert.equal(pair.port2.state, "closed");
  ok(await bounded(scope.closeAsync()));
});

test("WASM scope close cancels parked reception and fences new admission", async (t) => {
  const { sdk, scope } = await fixture(t);
  const pair = channel(t, sdk);
  const unused = channel(t, sdk);
  const stream = ok(scope.receiveMessages(pair.port2));
  const pending = observe(stream.next());
  const terminal = observe(stream.closed);
  const closing = scope.closeAsync();
  const refused = scope.receiveMessages(unused.port2);
  assert.equal(refused.outcome, "err");
  assert.equal(unused.port2.state, "open");
  ok(await bounded(closing));
  failed(await bounded(pending), "aborted");
  failed(await bounded(terminal), "aborted");
  assert.equal(pair.port2.state, "closed");
  const independent = unused.port2.receiveStream();
  await independent.return();
});

test("WASM ancestor close drains multiple descendant message endpoints", async (t) => {
  const { sdk, scope } = await fixture(t);
  const child = ok(scope.enterScope("child"));
  const grandchild = ok(child.enterScope("grandchild"));
  const first = channel(t, sdk);
  const second = channel(t, sdk);
  const receivers = [
    ok(child.receiveMessages(first.port2)),
    ok(grandchild.receiveMessages(second.port2)),
  ];
  const pending = receivers.map((stream) => observe(stream.next()));
  const terminals = receivers.map((stream) => observe(stream.closed));
  ok(await bounded(scope.closeAsync()));
  for (const result of await bounded(Promise.all([...pending, ...terminals]))) {
    failed(result, "aborted");
  }
  assert.equal(first.port2.state, "closed");
  assert.equal(second.port2.state, "closed");
});

test("WASM runtime close drains native BroadcastChannel reception", async (t) => {
  const { sdk, scope, closeRuntime } = await fixture(t);
  const name = `asupersync-wasm-message-${process.pid}-${Date.now()}`;
  const sender = sdk.createBrowserBroadcastChannel(name, authority);
  const receiver = sdk.createBrowserBroadcastChannel(name, authority);
  t.after(() => { sender.close(); receiver.close(); });
  const stream = ok(scope.receiveMessages(receiver));
  const delivered = stream.next();
  sender.post("broadcast-through-owned-receiver");
  assert.equal((await bounded(delivered)).value, "broadcast-through-owned-receiver");
  const pending = observe(stream.next());
  const terminal = observe(stream.closed);
  await closeRuntime();
  failed(await bounded(pending), "aborted");
  failed(await bounded(terminal), "aborted");
  assert.equal(receiver.state, "closed");
});

test("WASM receiver abort publishes cancellation and releases the scope task", async (t) => {
  const { sdk, scope } = await fixture(t);
  const pair = channel(t, sdk);
  const controller = new AbortController();
  const stream = ok(scope.receiveMessages(pair.port2, { signal: controller.signal }));
  const pending = observe(stream.next());
  const terminal = observe(stream.closed);
  controller.abort();
  failed(await bounded(pending), "aborted");
  failed(await bounded(terminal), "aborted");
  ok(await bounded(scope.closeAsync()));
});

test("WASM receiver overflow publishes its terminal without retained payloads", async (t) => {
  const { sdk, scope } = await fixture(t);
  const pair = channel(t, sdk);
  const stream = ok(scope.receiveMessages(pair.port2, { maxQueuedMessages: 1 }));
  const terminal = observe(stream.closed);
  pair.port1.send("first");
  pair.port1.send("overflow");
  failed(await bounded(terminal), "message_limit_exceeded");
  failed(await bounded(observe(stream.next())), "message_limit_exceeded");
  assert.equal(stream.queuedMessages, 0);
  assert.equal(pair.port2.state, "closed");
  ok(await bounded(scope.closeAsync()));
});

test("WASM message admission leaves invalid and pre-aborted sources unowned", async (t) => {
  const { sdk, scope } = await fixture(t);
  const pair = channel(t, sdk);
  assert.equal(scope.receiveMessages(pair.port2, { maxQueuedMessages: 0 }).outcome, "err");
  const controller = new AbortController();
  controller.abort();
  assert.equal(scope.receiveMessages(pair.port2, { signal: controller.signal }).outcome, "cancelled");
  assert.equal(pair.port2.state, "open");
  const stream = ok(scope.receiveMessages(pair.port2));
  await bounded(stream.return());
  ok(await bounded(scope.closeAsync()));
});

test("WASM message async-iterator break awaits owned task retirement", async (t) => {
  const { sdk, scope } = await fixture(t);
  const pair = channel(t, sdk);
  const stream = ok(scope.receiveMessages(pair.port2));
  pair.port1.send("stop");
  await bounded((async () => {
    for await (const value of stream) {
      assert.equal(value, "stop");
      break;
    }
  })());
  await bounded(stream.closed);
  assert.equal(pair.port2.state, "closed");
  ok(await bounded(scope.closeAsync()));
});

test("WASM message peer EOF retires its owned task", async (t) => {
  const { sdk, scope } = await fixture(t);
  const pair = channel(t, sdk);
  const stream = ok(scope.receiveMessages(pair.port2));
  const pending = stream.next();
  pair.port1.close();
  assert.equal((await bounded(pending)).done, true);
  await bounded(stream.closed);
  ok(await bounded(scope.closeAsync()));
});

test("WASM synchronous owner close preserves ABI refusal or cleans accepted closure", async (t) => {
  const { sdk, scope } = await fixture(t);
  const pair = channel(t, sdk);
  const stream = ok(scope.receiveMessages(pair.port2));
  const pending = observe(stream.next());
  const terminal = observe(stream.closed);
  const closed = scope.close();
  if (closed.outcome === "ok") {
    failed(await bounded(pending), "aborted");
    failed(await bounded(terminal), "aborted");
    assert.equal(pair.port2.state, "closed");
  } else {
    assert.equal(closed.outcome, "err");
    assert.equal(pair.port2.state, "open");
    await bounded(stream.return());
    assert.equal((await bounded(pending)).value.done, true);
    assert.equal((await bounded(terminal)).ok, true);
    ok(await bounded(scope.closeAsync()));
  }
});

test("WASM message admission refuses untracked core-created scope ownership", async (t) => {
  const { sdk, scope } = await fixture(t);
  const pair = channel(t, sdk);
  const rawChild = ok(sdk.scopeEnter({ parent: scope.core, label: "raw-child" }));
  const untracked = new sdk.RegionHandle(rawChild);
  assert.equal(untracked.receiveMessages(pair.port2).outcome, "err");
  assert.equal(pair.port2.state, "open");
  const independent = pair.port2.receiveStream();
  await bounded(independent.return());
  ok(await bounded(scope.closeAsync()));
});

test("WASM synchronous owner close during host preflight cannot admit an orphan", async (t) => {
  const { sdk, scope } = await fixture(t);
  const raw = new MessageChannel();
  t.after(() => { raw.port1.close(); raw.port2.close(); });
  let closeDuringPreflight = false;
  let ownerClose;
  const host = {
    addEventListener: (...args) => raw.port2.addEventListener(...args),
    removeEventListener: (...args) => raw.port2.removeEventListener(...args),
    postMessage: (...args) => raw.port2.postMessage(...args),
    start: () => raw.port2.start(),
    get close() {
      if (closeDuringPreflight) {
        closeDuringPreflight = false;
        ownerClose = scope.close();
      }
      return () => raw.port2.close();
    },
  };
  const source = sdk.createBrowserMessagePort(host, authority);
  closeDuringPreflight = true;
  assert.equal(scope.receiveMessages(source).outcome, "err");
  ok(ownerClose);
  assert.equal(source.state, "open");
  await bounded(source.receiveStream().return());
});

test("WASM synchronous owner close during port activation cannot leave a live receiver", async (t) => {
  const { sdk, scope } = await fixture(t);
  const raw = new MessageChannel();
  t.after(() => { raw.port1.close(); raw.port2.close(); });
  let ownerClose;
  const host = {
    addEventListener: (...args) => raw.port2.addEventListener(...args),
    removeEventListener: (...args) => raw.port2.removeEventListener(...args),
    postMessage: (...args) => raw.port2.postMessage(...args),
    close: () => raw.port2.close(),
    start() {
      ownerClose = scope.close();
      raw.port2.start();
    },
  };
  const source = sdk.createBrowserMessagePort(host, { ...authority, start: false });
  const admitted = scope.receiveMessages(source);
  assert.ok(ownerClose, "activation must attempt the real synchronous ABI close");
  if (ownerClose.outcome === "ok") {
    assert.equal(source.state, "closed");
    if (admitted.outcome === "ok") {
      failed(await bounded(observe(admitted.value.next())), "aborted");
      failed(await bounded(observe(admitted.value.closed)), "aborted");
    } else {
      assert.ok(admitted.outcome === "err" || admitted.outcome === "cancelled");
    }
  } else {
    assert.equal(ownerClose.outcome, "err");
    await bounded(ok(admitted).return());
    ok(await bounded(scope.closeAsync()));
  }
});

test("WASM owner starts message cleanup while native fetch cancellation awaits it", async (t) => {
  let releaseFetchCleanup;
  let fetchCleanupStarted = false;
  let messageEndpointClosed = false;
  const messageClosed = new Promise((resolve) => { releaseFetchCleanup = resolve; });
  const body = new ReadableStream({
    cancel() {
      fetchCleanupStarted = true;
      return messageClosed;
    },
  });
  // The response host is controlled; the body stream, message endpoints, SDK
  // ownership code, and task ABI are the actual implementations.
  const { sdk, scope } = await fixture(t, {
    globals: { fetch: async () => new Response(body) },
    runtimeOptions: {
      fetchAuthority: { allowedOrigins: ["https://message-cleanup.test"], allowedMethods: ["GET"] },
    },
  });
  const raw = new MessageChannel();
  t.after(() => { releaseFetchCleanup(); raw.port1.close(); raw.port2.close(); });
  const close = raw.port2.close.bind(raw.port2);
  raw.port2.close = () => {
    messageEndpointClosed = true;
    releaseFetchCleanup();
    close();
  };
  const source = sdk.createBrowserMessagePort(raw.port2, authority);
  const messages = ok(scope.receiveMessages(source));
  const pending = observe(messages.next());
  const request = ok(scope.fetch({ url: "https://message-cleanup.test/stream" }));
  ok(await bounded(request.response()));
  ok(await bounded(scope.closeAsync()));
  failed(await bounded(pending), "aborted");
  assert.equal(fetchCleanupStarted, true);
  assert.equal(messageEndpointClosed, true);
  assert.equal(body.locked, false);
});

function pipeDeferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
async function pipePending(promise) {
  let settled = false;
  void promise.then(() => { settled = true; }, () => { settled = true; });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(settled, false, "owned pipe completion cannot outrun native cleanup");
}
function parkedPipe(source = {}, sink = {}) {
  return {
    readable: new ReadableStream(source, { highWaterMark: 0 }),
    writable: new WritableStream(sink),
  };
}
function pipeUnlocked(readable, writable) {
  assert.equal(readable.locked, false, "native readable lock released");
  assert.equal(writable.locked, false, "native writable lock released");
}

test("WASM stream pipe preserves arbitrary chunks and owns the task through sink close", { timeout: 5000 }, async t => {
  const closingSink = pipeDeferred(), release = pipeDeferred();
  t.after(release.resolve);
  const { scope, snapshot } = await fixture(t);
  const chunks = [{ sequence: 1 }, "text", Uint8Array.of(0, 255), undefined, null];
  const received = [];
  let next = 0;
  const { readable, writable } = parkedPipe({
    pull(controller) {
      if (next === chunks.length) controller.close();
      else controller.enqueue(chunks[next++]);
    },
  }, {
    write(chunk) { received.push(chunk); },
    close() { closingSink.resolve(); return release.promise; },
  });
  assert.equal(snapshot().tasks.total, 0);
  const handle = ok(scope.pipeTo(readable, writable));
  assert.equal(snapshot().tasks.total, 1, "pipe admission creates an actual checked-in ABI task");
  await bounded(closingSink.promise);
  await pipePending(handle.closed);
  assert.equal(snapshot().tasks.total, 1, "sink close still belongs to the live task");
  assert.equal(received.length, chunks.length);
  for (let i = 0; i < chunks.length; i++) assert.equal(received[i], chunks[i]);
  release.resolve();
  ok(await bounded(handle.closed));
  ok(await bounded(handle.retire()));
  pipeUnlocked(readable, writable);
  assert.equal(snapshot().tasks.total, 0);
  assert.equal(snapshot().tasks.cleanup_pending, 0);
  ok(await bounded(scope.closeAsync()));
});

test("WASM scope close waits for a parked pipe write and both native cleanup promises", { timeout: 5000 }, async t => {
  const writing = pipeDeferred(), releaseWrite = pipeDeferred();
  const aborting = pipeDeferred(), releaseAbort = pipeDeferred();
  const cancelling = pipeDeferred(), releaseCancel = pipeDeferred();
  t.after(() => { releaseWrite.resolve(); releaseAbort.resolve(); releaseCancel.resolve(); });
  const { scope, snapshot } = await fixture(t);
  let pulled = false;
  const events = [];
  const { readable, writable } = parkedPipe({
    pull(controller) { if (!pulled) { pulled = true; controller.enqueue("pending write"); } },
    cancel() { events.push("source cancel"); cancelling.resolve(); return releaseCancel.promise; },
  }, {
    write() { events.push("write"); writing.resolve(); return releaseWrite.promise; },
    abort() { events.push("sink abort"); aborting.resolve(); return releaseAbort.promise; },
    close() { assert.fail("cancelled pipe must not report graceful sink close"); },
  });
  const handle = ok(scope.pipeTo(readable, writable));
  await bounded(writing.promise);
  const closing = scope.closeAsync();
  await pipePending(closing);
  await pipePending(handle.closed);
  assert.equal(snapshot().tasks.total, 1);
  const unused = parkedPipe();
  assert.equal(scope.pipeTo(unused.readable, unused.writable).outcome, "err");
  pipeUnlocked(unused.readable, unused.writable);
  releaseWrite.resolve();
  await bounded(Promise.all([aborting.promise, cancelling.promise]));
  await pipePending(closing);
  releaseAbort.resolve();
  await pipePending(closing);
  assert.equal(snapshot().tasks.total, 1);
  releaseCancel.resolve();
  ok(await bounded(closing));
  assert.equal((await bounded(handle.closed)).outcome, "cancelled");
  assert.deepEqual(events, ["write", "sink abort", "source cancel"]);
  pipeUnlocked(readable, writable);
  assert.equal(snapshot().tasks.total, 0);
  assert.equal(snapshot().tasks.cleanup_pending, 0);
  console.log(JSON.stringify({
    scenario_id: "browser-pipe-native-cleanup-packaged-wasm",
    wasm_task_counts: [0, 1, 1, 0],
    pending_owner_close_before_native_cleanup: true,
    native_readable_locked: readable.locked, native_writable_locked: writable.locked,
    evidence_scope: "actual SDK; checked-in JS/WASM handle ledger; native Node WHATWG streams",
    no_claim: ["browser-engine execution", "Rust rebuild", "Rust executor dispatch", "arbitrary-chunk byte bounds"],
  }));
});

test("WASM ancestor close drains descendant pipes while a sibling remains live", { timeout: 5000 }, async t => {
  const { runtime, scope, snapshot } = await fixture(t);
  const child = ok(scope.enterScope("pipe-child"));
  const grandchild = ok(child.enterScope("pipe-grandchild"));
  const sibling = ok(runtime.enterScope("pipe-sibling"));
  const first = parkedPipe(), second = parkedPipe(), independent = parkedPipe();
  const a = ok(child.pipeTo(first.readable, first.writable));
  const b = ok(grandchild.pipeTo(second.readable, second.writable));
  const c = ok(sibling.pipeTo(independent.readable, independent.writable));
  assert.equal(snapshot().tasks.total, 3);
  ok(await bounded(scope.closeAsync()));
  assert.equal((await bounded(a.closed)).outcome, "cancelled");
  assert.equal((await bounded(b.closed)).outcome, "cancelled");
  await pipePending(c.closed);
  assert.equal(snapshot().tasks.total, 1, "ancestor closure must preserve independent ownership");
  pipeUnlocked(first.readable, first.writable);
  pipeUnlocked(second.readable, second.writable);
  ok(await bounded(sibling.closeAsync()));
  assert.equal((await bounded(c.closed)).outcome, "cancelled");
  pipeUnlocked(independent.readable, independent.writable);
  assert.equal(snapshot().tasks.total, 0);
});

test("WASM runtime close drains every native stream pipe", { timeout: 5000 }, async t => {
  const { runtime, scope, closeRuntime, snapshot } = await fixture(t);
  const other = ok(runtime.enterScope("second-pipe-root"));
  const first = parkedPipe(), second = parkedPipe();
  const handles = [ok(scope.pipeTo(first.readable, first.writable)),
    ok(other.pipeTo(second.readable, second.writable))];
  assert.equal(snapshot().tasks.total, 2);
  await closeRuntime();
  for (const handle of handles) assert.equal((await bounded(handle.closed)).outcome, "cancelled");
  pipeUnlocked(first.readable, first.writable);
  pipeUnlocked(second.readable, second.writable);
  assert.equal(snapshot().tasks.total, 0);
  assert.equal(snapshot().tasks.cleanup_pending, 0);
});

test("WASM pipe cancellation borrows the caller signal without mutating it", { timeout: 5000 }, async t => {
  const { scope, snapshot } = await fixture(t);
  const controller = new AbortController();
  const add = controller.signal.addEventListener, remove = controller.signal.removeEventListener;
  const before = getEventListeners(controller.signal, "abort").length;
  const first = parkedPipe();
  const a = ok(scope.pipeTo(first.readable, first.writable, { signal: controller.signal }));
  assert.equal((await bounded(a.cancel("caller cancellation"))).outcome, "cancelled");
  assert.equal(controller.signal.aborted, false);
  assert.equal(controller.signal.addEventListener, add);
  assert.equal(controller.signal.removeEventListener, remove);
  assert.equal(getEventListeners(controller.signal, "abort").length, before);
  assert.equal(snapshot().tasks.total, 0);
  pipeUnlocked(first.readable, first.writable);

  const second = parkedPipe();
  const b = ok(scope.pipeTo(second.readable, second.writable, { signal: controller.signal }));
  const reason = { private: "caller-owned signal reason" };
  controller.abort(reason);
  assert.equal((await bounded(b.closed)).outcome, "cancelled");
  assert.equal(controller.signal.reason, reason);
  assert.equal(snapshot().tasks.total, 0);
  pipeUnlocked(second.readable, second.writable);
});

test("WASM pipe admission leaves locked, pre-aborted, and untracked sources untouched", { timeout: 5000 }, async t => {
  const { sdk, scope, snapshot } = await fixture(t);
  let pulls = 0, cancels = 0, aborts = 0;
  const { readable, writable } = parkedPipe({
    pull() { pulls++; }, cancel() { cancels++; },
  }, { abort() { aborts++; } });
  const reader = readable.getReader();
  assert.equal(scope.pipeTo(readable, writable).outcome, "err");
  reader.releaseLock();
  const writer = writable.getWriter();
  assert.equal(scope.pipeTo(readable, writable).outcome, "err");
  writer.releaseLock();
  const controller = new AbortController();
  controller.abort();
  assert.equal(scope.pipeTo(readable, writable, { signal: controller.signal }).outcome, "cancelled");
  const rawChild = ok(sdk.scopeEnter({ parent: scope.core, label: "raw-pipe-child" }));
  const untracked = new sdk.RegionHandle(rawChild);
  assert.equal(untracked.pipeTo(readable, writable).outcome, "err");
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual([pulls, cancels, aborts, snapshot().tasks.total], [0, 0, 0, 0]);
  pipeUnlocked(readable, writable);
});

test("WASM native pipe cleanup failure is not a successful owner drain", { timeout: 5000 }, async t => {
  const { scope, snapshot } = await fixture(t);
  const { readable, writable } = parkedPipe({}, {
    abort() { throw new Error("PRIVATE_PIPE_CLEANUP_DETAIL"); },
  });
  const handle = ok(scope.pipeTo(readable, writable));
  const closing = await bounded(scope.closeAsync());
  assert.equal(closing.outcome, "err");
  const terminal = await bounded(handle.closed);
  assert.equal(terminal.outcome, "err");
  assert.doesNotMatch(JSON.stringify({ closing, terminal }), /PRIVATE_PIPE_CLEANUP_DETAIL/);
  pipeUnlocked(readable, writable);
  assert.equal(snapshot().tasks.total, 0, "settled failure still retires the terminal ABI task");
  ok(await bounded(scope.closeAsync()));
});

test("WASM synchronous scope close preserves live-pipe ownership on ABI refusal", { timeout: 5000 }, async t => {
  const { scope, snapshot } = await fixture(t);
  const { readable, writable } = parkedPipe();
  const handle = ok(scope.pipeTo(readable, writable));
  const closing = scope.close();
  if (closing.outcome === "ok") {
    assert.equal((await bounded(handle.closed)).outcome, "cancelled");
    pipeUnlocked(readable, writable);
  } else {
    assert.equal(closing.outcome, "err");
    assert.equal(snapshot().tasks.total, 1);
    await pipePending(handle.closed);
    ok(await bounded(scope.closeAsync()));
    assert.equal((await bounded(handle.closed)).outcome, "cancelled");
    pipeUnlocked(readable, writable);
  }
  assert.equal(snapshot().tasks.total, 0);
});

test("WASM scope drain unifies live HTTP fetch with a backpressured owned pipe", { timeout: 5000 }, async t => {
  const writing = pipeDeferred(), releaseWrite = pipeDeferred();
  const aborting = pipeDeferred(), releaseAbort = pipeDeferred(), disconnected = pipeDeferred();
  const payload = Buffer.from([4, 8, 15, 16, 23, 42]);
  let requests = 0, peerEnded = false, sinkCloses = 0;
  const received = [];
  const server = createServer((_request, response) => {
    requests++;
    response.on("error", () => {});
    response.on("close", disconnected.resolve);
    response.writeHead(200, { "content-type": "application/octet-stream" });
    response.flushHeaders();
    response.write(payload);
    // Deliberately keep the response open: received bytes are evidence of live
    // streaming and owner cancellation must disconnect this real HTTP peer.
    peerEnded = response.writableEnded;
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    releaseWrite.resolve();
    releaseAbort.resolve();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  });
  const origin = "http://127.0.0.1:" + server.address().port;
  const { scope, snapshot } = await fixture(t, {
    globals: { fetch },
    runtimeOptions: {
      fetchAuthority: { allowedOrigins: [origin], allowedMethods: ["GET"] },
    },
  });
  const request = ok(scope.fetch({ url: origin + "/owned-live-pipe" }));
  assert.equal(ok(await bounded(request.response())).status, 200);
  const readable = ok(request.toReadableStream());
  const writable = new WritableStream({
    write(bytes) {
      received.push(...bytes);
      writing.resolve();
      return releaseWrite.promise;
    },
    abort() { aborting.resolve(); return releaseAbort.promise; },
    close() { sinkCloses++; },
  });
  const pipe = ok(scope.pipeTo(readable, writable));
  await bounded(writing.promise);
  assert.deepEqual(received, [...payload]);
  assert.equal(peerEnded, false, "the real response has not reached EOF");
  assert.equal(requests, 1);
  assert.equal(snapshot().tasks.total, 2, "fetch and pipe have independent owned tasks");
  await pipePending(request.closed);
  await pipePending(pipe.closed);

  const closing = scope.closeAsync();
  await bounded(disconnected.promise);
  assert.equal((await bounded(request.closed)).outcome, "cancelled");
  await pipePending(closing);
  assert.equal(snapshot().tasks.total, 1, "pipe still owns the in-flight native sink write");
  releaseWrite.resolve();
  await bounded(aborting.promise);
  await pipePending(closing);
  await pipePending(pipe.closed);
  releaseAbort.resolve();

  ok(await bounded(closing));
  assert.equal((await bounded(pipe.closed)).outcome, "cancelled",
    "normal owner cancellation of the fetch source is not a pipe cleanup failure");
  assert.equal(sinkCloses, 0);
  pipeUnlocked(readable, writable);
  assert.equal(snapshot().tasks.total, 0);
  assert.equal(snapshot().tasks.cleanup_pending, 0);
  console.log(JSON.stringify({
    scenario_id: "browser-fetch-pipe-owned-drain-packaged-wasm",
    live_streamed_bytes: received.length, requests, peer_response_reached_eof: peerEnded,
    peer_disconnected_before_owner_close: true, native_sink_abort_awaited: true,
    wasm_task_counts: [0, 2, 1, 0],
    evidence_scope: "actual SDK; checked-in JS/WASM handle ledger; native Node fetch/HTTP/WHATWG streams",
    no_claim: ["browser-engine execution", "Rust rebuild", "Rust executor dispatch"],
  }));
});
