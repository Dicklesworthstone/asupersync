/**
 * Region-owned reception over actual SDK source, the checked-in WASM ABI,
 * and Node's native MessageChannel/BroadcastChannel implementations.
 * This harness supplies browser-like globals for SDK admission; it is not a
 * browser-engine run, a Rust rebuild, or proof of Rust executor dispatch.
 * node --unhandled-rejections=strict --experimental-vm-modules --test scripts/test_browser_message_regions_wasm.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { createContext, SourceTextModule, runInContext } from "node:vm";
import { BroadcastChannel, MessageChannel } from "node:worker_threads";

const files = [
  ["sdk", "packages/browser/src/index.ts", true],
  ["@asupersync/browser-core", "packages/browser-core/index.js", false],
  ["./fetch.js", "packages/browser/src/fetch.ts", true],
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
  evidence_scope: "actual SDK, checked-in generated JS/WASM ABI, native Node message hosts",
  no_claim: ["browser-engine execution", "Rust rebuild", "Rust executor dispatch"],
  source_sha256: hashes,
}));

async function loadSdk(globals = {}) {
  const context = createContext({
    console, AbortController, ArrayBuffer, DataView, Uint8Array, URL,
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
  return entry.namespace;
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
  const sdk = await loadSdk(options.globals);
  const runtime = ok(await sdk.createBrowserRuntime({ ...options.runtimeOptions, eagerInit: false }));
  const scope = ok(runtime.enterScope("message-receive-integration"));
  let runtimeClosed = false;
  const closeRuntime = async () => {
    if (runtimeClosed) return;
    ok(await bounded(runtime.closeAsync()));
    runtimeClosed = true;
  };
  t.after(closeRuntime);
  return { sdk, runtime, scope, closeRuntime };
}
function channel(t, sdk) {
  const pair = sdk.createBrowserMessageChannel(authority);
  t.after(() => pair.close());
  return pair;
}

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
