/**
 * Public Browser SDK reliable-stream integration regressions. Replay (Node 24+):
 * node --experimental-vm-modules --test --test-concurrency=1 \
 *   scripts/test_browser_sdk_webtransport_streams.mjs
 *
 * The real TypeScript SDK is transformed in memory and linked to the real core
 * facade and shared stream manager. Only the generated WASM ABI is replaced by
 * an intentional call recorder. Native WHATWG streams supply actual locking,
 * backpressure, EOF and cancellation behavior; the host session is controlled.
 * This proves the public JS/host boundary and ABI requests, not Rust dispatcher
 * execution, packaged WASM, a real browser, or live HTTP/3 interoperability.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";

const sdkPath = process.env.ASUPERSYNC_BROWSER_SDK_SOURCE
  ?? fileURLToPath(new URL("../packages/browser/src/index.ts", import.meta.url));
const corePath = process.env.ASUPERSYNC_BROWSER_CORE_SOURCE
  ?? fileURLToPath(new URL("../packages/browser-core/index.js", import.meta.url));
const managerPath = process.env.ASUPERSYNC_WEBTRANSPORT_STREAM_SOURCE
  ?? fileURLToPath(new URL("../packages/browser-core/webtransport-streams.js", import.meta.url));
const fetchPath = process.env.ASUPERSYNC_BROWSER_FETCH_SOURCE
  ?? fileURLToPath(new URL("../packages/browser/src/fetch.ts", import.meta.url));
const sdkSource = readFileSync(sdkPath, "utf8");
const coreSource = readFileSync(corePath, "utf8");
const managerSource = readFileSync(managerPath, "utf8");
const fetchSource = readFileSync(fetchPath, "utf8");
const sdkJavaScript = stripTypeScriptTypes(sdkSource, { mode: "transform" });
const fetchJavaScript = stripTypeScriptTypes(fetchSource, { mode: "transform" });

console.log(JSON.stringify({
  scenario_id: "browser-sdk-webtransport-reliable-streams",
  sources: Object.fromEntries([
    ["sdk", sdkSource], ["core", coreSource], ["streams", managerSource], ["fetch", fetchSource],
  ].map(([name, source]) => [name, createHash("sha256").update(source).digest("hex")])),
  evidence_scope: "actual SDK/core/shared manager, native WHATWG streams, intentional WASM ABI recorder",
  no_claim: ["Rust dispatcher execution", "packaged WASM", "browser conformance", "live HTTP/3"],
}));

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

const turn = () => new Promise((resolve) => setImmediate(resolve));
const clone = (value) => structuredClone(value);
const unitJson = '{"outcome":"ok","value":{"kind":"unit"}}';

function assertSameHandle(recorded, actual) {
  const normalized = clone(actual.toJSON());
  normalized.owner_token = String(normalized.owner_token);
  assert.deepEqual({ ...recorded, owner_token: String(recorded.owner_token) }, normalized);
}

function unwrap(outcome) {
  assert.equal(outcome.outcome, "ok", JSON.stringify(outcome));
  return outcome.value;
}

function bytes(outcome) {
  const result = unwrap(outcome);
  assert.equal(result.done, false);
  return Array.from(result.value);
}

function cancelled(outcome) {
  assert.equal(outcome.outcome, "cancelled", JSON.stringify(outcome));
  return outcome.cancellation;
}

function byteStream(options = {}) {
  const events = [];
  let input;
  const readable = new ReadableStream({
    start(controller) { input = controller; },
    cancel(reason) { events.push(["cancel", reason]); return options.cancel?.(reason); },
  });
  const writable = new WritableStream({
    write(value) {
      events.push(["write", Array.from(value)]);
      return options.write?.(value);
    },
    close() { events.push(["finish"]); return options.finish?.(); },
    abort(reason) { events.push(["abort", reason]); return options.abort?.(reason); },
  });
  return { readable, writable, input, events };
}

async function fixture(t, options = {}) {
  const hosts = [];
  const calls = { init: 0, runtimeCreate: [], scopeEnter: [], spawn: [], join: [], cancel: [], scopeClose: [], runtimeClose: [] };
  let nextRuntime = 1;
  let nextRegion = 100;
  let nextTask = 1;

  class ControlledTransport {
    constructor(url, configuration) {
      this.url = url;
      this.configuration = configuration;
      this.events = [];
      this.streams = [];
      this.handshake = deferred();
      this.ready = this.handshake.promise;
      this.completion = deferred();
      this.closed = this.completion.promise;
      if (!options.pendingHandshake) this.handshake.resolve();
      this.datagrams = {
        readable: new ReadableStream({
          start: (controller) => { this.datagramInput = controller; },
          cancel: (reason) => { this.events.push(["datagram-cancel", reason]); },
        }),
        writable: new WritableStream({
          write: (value) => { this.events.push(["datagram-write", Array.from(value)]); },
          abort: (reason) => { this.events.push(["datagram-abort", reason]); },
        }),
      };
      this.incomingBidirectionalStreams = new ReadableStream({
        start: (controller) => { this.bidirectionalInput = controller; },
        cancel: (reason) => { this.events.push(["incoming-bidi-cancel", reason]); },
      });
      this.incomingUnidirectionalStreams = new ReadableStream({
        start: (controller) => { this.unidirectionalInput = controller; },
        cancel: (reason) => { this.events.push(["incoming-uni-cancel", reason]); },
      });
      hosts.push(this);
    }

    createBidirectionalStream() {
      this.events.push(["create-bidirectional"]);
      if (options.createBidirectional) return options.createBidirectional(this);
      const host = byteStream(options.streamOptions);
      this.streams.push(host);
      return Promise.resolve(host);
    }

    createUnidirectionalStream() {
      this.events.push(["create-unidirectional"]);
      const host = byteStream(options.streamOptions);
      this.streams.push(host);
      return Promise.resolve(host.writable);
    }

    close(info = {}) {
      this.events.push(["close", info]);
      this.completion.resolve(info);
    }
  }

  const context = createContext({
    AbortController, ArrayBuffer, Uint8Array, URL, TextEncoder, TextDecoder,
    ReadableStream, WritableStream, WebAssembly, Error, TypeError, RangeError,
    DOMException, structuredClone, queueMicrotask, setTimeout, clearTimeout,
    window: {}, document: {}, isSecureContext: true,
    WebTransport: ControlledTransport,
  });
  const handle = (kind, slot) => JSON.stringify({ kind, slot, generation: 1, owner_token: "42" });
  const names = [
    "default", "abi_fingerprint", "abi_version", "fetch_request",
    "runtime_close", "runtime_create", "scope_close", "scope_enter",
    "task_cancel", "task_join", "task_spawn", "websocket_cancel",
    "websocket_close", "websocket_open", "websocket_recv", "websocket_send",
  ];
  const implementations = {
    default: async () => { calls.init += 1; },
    abi_fingerprint: () => "4558451663113424898",
    abi_version: () => '{"major":1,"minor":0}',
    runtime_create: (request) => {
      calls.runtimeCreate.push(JSON.parse(request));
      return handle("runtime", nextRuntime++);
    },
    scope_enter: (request) => {
      calls.scopeEnter.push(JSON.parse(request));
      return handle("region", nextRegion++);
    },
    task_spawn: (request) => {
      calls.spawn.push(JSON.parse(request));
      return handle("task", nextTask++);
    },
    task_join: (task, outcome, version) => {
      calls.join.push({ task: JSON.parse(task), outcome: JSON.parse(outcome), version });
      return outcome;
    },
    task_cancel: (request) => { calls.cancel.push(JSON.parse(request)); return options.cancelResponse ?? unitJson; },
    scope_close: (region) => { calls.scopeClose.push(JSON.parse(region)); return unitJson; },
    runtime_close: (runtime) => { calls.runtimeClose.push(JSON.parse(runtime)); return unitJson; },
  };
  const bindings = new SyntheticModule(names, function () {
    for (const name of names) {
      this.setExport(name, implementations[name] ?? (() => {
        throw new Error(`Unexpected raw ABI call: ${name}`);
      }));
    }
  }, { context });
  const coreModule = new SourceTextModule(coreSource, { context, identifier: corePath });
  const managerModule = new SourceTextModule(managerSource, { context, identifier: managerPath });
  const fetchModule = new SourceTextModule(fetchJavaScript, { context, identifier: fetchPath });
  const sdkModule = new SourceTextModule(sdkJavaScript, { context, identifier: sdkPath });
  await sdkModule.link((specifier) => {
    if (specifier === "@asupersync/browser-core") return coreModule;
    if (specifier === "./fetch.js") return fetchModule;
    if (specifier === "@asupersync/browser-core/webtransport-streams"
      || specifier === "@asupersync/browser-core/webtransport-streams.js"
      || specifier === "./webtransport-streams.js") return managerModule;
    assert.equal(specifier, "./asupersync.js", "no SDK or core implementation may be mocked");
    return bindings;
  });
  await sdkModule.evaluate();
  const sdk = sdkModule.namespace;
  const runtime = unwrap(await sdk.createBrowserRuntime());
  const scope = unwrap(runtime.enterScope("reliable-stream-regression"));
  t.after(async () => {
    runtime.close();
    await turn();
  });
  function open(owner = scope) {
    const session = unwrap(owner.openWebTransport("https://transport.example.test/session"));
    return { session, host: hosts.at(-1) };
  }
  return { sdk, runtime, scope, open, hosts, calls };
}

function assertUnlocked(host) {
  assert.equal(host.readable.locked, false);
  assert.equal(host.writable.locked, false);
}

function closeCount(host) {
  return host.events.filter(([event]) => event === "close").length;
}

test("SDK-WT-MODES: one session and one task support all four reliable stream modes", { timeout: 5000 }, async (t) => {
  let writeGate = deferred();
  const { open, hosts, calls, scope } = await fixture(t, { streamOptions: { write: () => writeGate.promise } });
  const { session, host } = open();
  unwrap(await session.ready());
  assert.equal(hosts.length, 1);
  assert.equal(calls.spawn.length, 1);
  assertSameHandle(calls.spawn[0].scope, scope);

  const outgoing = unwrap(await session.openStream());
  assert.equal(outgoing.direction, "bidirectional");
  const outgoingHost = host.streams[0];
  const payload = new Uint8Array([1, 2, 3]);
  let writeSettled = false;
  const writing = outgoing.write(payload).then((outcome) => { writeSettled = true; return outcome; });
  payload.fill(99);
  await turn();
  assert.equal(writeSettled, false, "host write backpressure reaches the SDK caller");
  assert.deepEqual(outgoingHost.events, [["write", [1, 2, 3]]], "the admitted write owns its byte snapshot");
  writeGate.resolve();
  unwrap(await writing);
  outgoingHost.input.enqueue(new Uint8Array([4]));
  outgoingHost.input.enqueue(new Uint8Array([5, 6]));
  outgoingHost.input.close();
  assert.deepEqual(bytes(await outgoing.read()), [4]);
  assert.deepEqual(bytes(await outgoing.read()), [5, 6]);
  assert.equal(unwrap(await outgoing.read()).done, true);
  unwrap(await outgoing.finish());
  unwrap(await outgoing.closed);
  assertUnlocked(outgoingHost);

  writeGate = deferred();
  const sending = unwrap(await session.openUnidirectionalStream());
  assert.equal(sending.direction, "unidirectional");
  assert.equal("read" in sending, false);
  let sendSettled = false;
  const send = sending.write(new Uint8Array([7, 8]).buffer).then((outcome) => { sendSettled = true; return outcome; });
  await turn();
  assert.equal(sendSettled, false, "send-only streams also retain native write backpressure");
  assert.deepEqual(host.streams[1].events, [["write", [7, 8]]]);
  writeGate.resolve();
  unwrap(await send);
  unwrap(await sending.finish());
  unwrap(await sending.closed);
  assert.deepEqual(host.streams[1].events, [["write", [7, 8]], ["finish"]]);
  assert.equal(host.streams[1].writable.locked, false);

  let acceptedSettled = false;
  const accepting = session.acceptBidirectionalStream().then((outcome) => { acceptedSettled = true; return outcome; });
  await turn();
  assert.equal(acceptedSettled, false, "accept waits for a peer stream");
  const incomingHost = byteStream();
  host.bidirectionalInput.enqueue(incomingHost);
  const incoming = unwrap(await accepting);
  assert.equal(incoming.direction, "bidirectional");
  unwrap(await incoming.write(new Uint8Array([9])));
  unwrap(await incoming.finish());
  assert.deepEqual(incomingHost.events, [["write", [9]], ["finish"]]);
  incomingHost.input.enqueue(new Uint8Array([10, 11]));
  incomingHost.input.close();
  assert.deepEqual(bytes(await incoming.read()), [10, 11]);
  assert.equal(unwrap(await incoming.read()).done, true);
  unwrap(await incoming.closed);
  assertUnlocked(incomingHost);

  const receivingHost = byteStream();
  host.unidirectionalInput.enqueue(receivingHost.readable);
  const receiving = unwrap(await session.acceptUnidirectionalStream());
  assert.equal(receiving.direction, "unidirectional");
  assert.equal("write" in receiving, false);
  receivingHost.input.enqueue(new Uint8Array([12, 13]));
  receivingHost.input.close();
  assert.deepEqual(bytes(await receiving.read()), [12, 13]);
  assert.equal(unwrap(await receiving.read()).done, true);
  unwrap(await receiving.closed);
  assert.equal(receivingHost.readable.locked, false);

  host.bidirectionalInput.close();
  host.unidirectionalInput.close();
  assert.equal(unwrap(await session.acceptBidirectionalStream()), null);
  assert.equal(unwrap(await session.acceptUnidirectionalStream()), null);
  assert.equal(host.incomingBidirectionalStreams.locked, false);
  assert.equal(host.incomingUnidirectionalStreams.locked, false);
  unwrap(await session.sendDatagram(new Uint8Array([14])));
  host.datagramInput.enqueue(new Uint8Array([15]));
  assert.deepEqual(Array.from(unwrap(await session.recvDatagram())), [15]);
  assert.equal(hosts.length, 1, "stream operations must not create a second host session");
  assert.equal(calls.spawn.length, 1, "all streams retain the original session task");
  cancelled(session.close({ reason: "modes complete" }));
  await turn();
  assert.equal(closeCount(host), 1);
  assert.equal(calls.join.length, 1);
});

test("SDK-WT-OWNERSHIP: nested close cancels descendants while parent and sibling remain usable", { timeout: 5000 }, async (t) => {
  const { runtime, scope, open, calls, hosts } = await fixture(t);
  const child = unwrap(scope.enterScope("child"));
  const grandchild = unwrap(child.enterScope("grandchild"));
  const sibling = unwrap(runtime.enterScope("sibling"));
  const parentSession = open(scope);
  const childSession = open(child);
  const grandchildSession = open(grandchild);
  const siblingSession = open(sibling);
  const entries = [];
  for (const owned of [parentSession, childSession, grandchildSession, siblingSession]) {
    const stream = unwrap(await owned.session.openStream());
    entries.push({ ...owned, stream, read: stream.read() });
  }
  const childAccept = childSession.session.acceptUnidirectionalStream();
  const grandchildAccept = grandchildSession.session.acceptBidirectionalStream();
  await turn();
  assert.equal(childSession.host.incomingUnidirectionalStreams.locked, true);
  assert.equal(grandchildSession.host.incomingBidirectionalStreams.locked, true);
  unwrap(child.close());
  for (const index of [1, 2]) {
    cancelled(await entries[index].read);
    cancelled(await entries[index].stream.closed);
    assertUnlocked(entries[index].host.streams[0]);
    assert.equal(closeCount(entries[index].host), 1);
  }
  cancelled(await childAccept);
  cancelled(await grandchildAccept);
  assert.equal(childSession.host.incomingUnidirectionalStreams.locked, false);
  assert.equal(grandchildSession.host.incomingBidirectionalStreams.locked, false);
  assert.equal(calls.scopeClose.length, 1);
  assertSameHandle(calls.scopeClose[0], child);

  for (const index of [0, 3]) {
    const entry = entries[index];
    assert.equal(closeCount(entry.host), 0);
    unwrap(await entry.stream.write(new Uint8Array([index, 21])));
    entry.host.streams[0].input.enqueue(new Uint8Array([index, 22]));
    assert.deepEqual(bytes(await entry.read), [index, 22]);
    entry.read = entry.stream.read();
  }
  unwrap(runtime.close());
  for (const index of [0, 3]) {
    cancelled(await entries[index].read);
    cancelled(await entries[index].stream.closed);
    assertUnlocked(entries[index].host.streams[0]);
  }
  assert.equal(hosts.length, 4);
  assert.equal(calls.spawn.length, 4);
  assert.ok(hosts.every((host) => closeCount(host) === 1));
  assert.ok(hosts.every((host) => !host.datagrams.readable.locked && !host.datagrams.writable.locked));
});

test("SDK-WT-DRAIN: stream cancellation waits for host write ownership and preserves a sibling", { timeout: 5000 }, async (t) => {
  const writeGate = deferred();
  const { open, calls } = await fixture(t, {
    createBidirectional(host) {
      const stream = byteStream(host.streams.length === 0 ? { write: () => writeGate.promise } : {});
      host.streams.push(stream);
      return Promise.resolve(stream);
    },
  });
  const { session, host } = open();
  const stopped = unwrap(await session.openStream());
  const survivor = unwrap(await session.openStream());
  const writing = stopped.write(new Uint8Array([30, 31]));
  const reading = stopped.read();
  await turn();
  assert.deepEqual(host.streams[0].events, [["write", [30, 31]]]);
  let drained = false;
  const cancelling = stopped.cancel("request no longer needed").then((outcome) => { drained = true; return outcome; });
  await turn();
  assert.equal(drained, false, "an in-flight native write remains owned until the sink settles");
  assert.equal(host.streams[0].writable.locked, true);
  unwrap(await survivor.write(new Uint8Array([32])));
  host.streams[1].input.enqueue(new Uint8Array([33]));
  assert.deepEqual(bytes(await survivor.read()), [33]);
  assert.equal(closeCount(host), 0);
  writeGate.resolve();
  const cancellation = cancelled(await cancelling);
  assert.equal(cancellation.kind, "webtransport_stream_cancel");
  assert.equal(cancellation.message, "request no longer needed");
  cancelled(await writing);
  cancelled(await reading);
  cancelled(await stopped.closed);
  assertUnlocked(host.streams[0]);
  assert.equal(host.streams[0].events.filter(([kind]) => kind === "abort").length, 1);
  assert.equal(calls.cancel.length, 0, "a stream cancel does not cancel the session task");
  assert.equal(calls.join.length, 0);
  host.streams[1].input.close();
  assert.equal(unwrap(await survivor.read()).done, true);
  unwrap(await survivor.finish());
  unwrap(await survivor.closed);
  cancelled(session.close());
});

test("SDK-WT-LATE: owner close cancels accept and disposes a host stream created afterwards", { timeout: 5000 }, async (t) => {
  const creation = deferred();
  const { scope, open, calls } = await fixture(t, { createBidirectional: () => creation.promise });
  const { session, host } = open();
  const opening = session.openStream();
  const accepting = session.acceptBidirectionalStream();
  await turn();
  assert.equal(host.events.filter(([kind]) => kind === "create-bidirectional").length, 1);
  assert.equal(host.incomingBidirectionalStreams.locked, true);
  unwrap(scope.close());
  cancelled(await accepting);
  assert.equal(closeCount(host), 1);
  const late = byteStream();
  creation.resolve(late);
  cancelled(await opening);
  assertUnlocked(late);
  assert.equal(late.events.filter(([kind]) => kind === "cancel").length, 1);
  assert.equal(late.events.filter(([kind]) => kind === "abort").length, 1);
  const rejected = await session.openUnidirectionalStream();
  assert.equal(rejected.outcome, "err");
  assert.equal(rejected.failure.code, "invalid_handle");
  assert.equal(host.events.some(([kind]) => kind === "create-unidirectional"), false);
  await turn();
  assert.equal(calls.join.length, 0, "scope teardown owns the task; late host callbacks cannot join it twice");
});

test("SDK-WT-TERMINAL: peer failure settles active and pending stream operations exactly once", { timeout: 5000 }, async (t) => {
  const unhandled = [];
  const onUnhandled = (error) => { unhandled.push(error); };
  process.on("unhandledRejection", onUnhandled);
  t.after(() => { process.off("unhandledRejection", onUnhandled); });
  const { open, calls } = await fixture(t);
  const { session, host } = open();
  const stream = unwrap(await session.openStream());
  const reading = stream.read();
  const accepting = session.acceptUnidirectionalStream();
  await turn();
  host.completion.reject(new Error("peer connection reset"));
  for (const outcome of await Promise.all([reading, accepting, stream.closed])) {
    assert.equal(outcome.outcome, "err", JSON.stringify(outcome));
    assert.equal(outcome.failure.code, "internal_failure");
    assert.match(outcome.failure.message, /peer connection reset/);
  }
  await turn();
  assertUnlocked(host.streams[0]);
  assert.equal(host.incomingUnidirectionalStreams.locked, false);
  assert.equal(host.datagrams.readable.locked, false);
  assert.equal(host.datagrams.writable.locked, false);
  assert.equal(calls.join.length, 1);
  assert.equal(calls.join[0].outcome.outcome, "err");
  session.close();
  await turn();
  assert.equal(calls.join.length, 1);
  assert.deepEqual(unhandled, []);
});

test("SDK-WT-AUTHORITY: every method derives its original session and rejects a foreign owner token", { timeout: 5000 }, async (t) => {
  const { sdk, open, hosts, calls } = await fixture(t);
  const original = open();
  const other = open();
  const foreign = new sdk.WebTransportHandle(new sdk.CoreTaskHandle({
    ...original.session.toJSON(), owner_token: "987",
  }));
  for (const method of ["openStream", "openUnidirectionalStream", "acceptBidirectionalStream", "acceptUnidirectionalStream"]) {
    const rejected = await foreign[method]();
    assert.equal(rejected.outcome, "err", method);
    assert.equal(rejected.failure.code, "invalid_handle", method);
  }
  assert.ok(hosts.every((host) => host.streams.length === 0));
  assert.ok(hosts.every((host) => !host.incomingBidirectionalStreams.locked && !host.incomingUnidirectionalStreams.locked));
  // JavaScript may supply extra arguments despite the no-argument TS contract.
  // They cannot retarget the capability to another session or direction.
  const writable = unwrap(await original.session.openUnidirectionalStream({
    session: other.session.core, direction: "bidirectional",
  }));
  assert.equal(writable.direction, "unidirectional");
  assert.equal(original.host.streams.length, 1);
  assert.equal(other.host.streams.length, 0);
  unwrap(await writable.write(new Uint8Array([40, 41])));
  unwrap(await writable.finish());
  unwrap(await writable.closed);
  assert.deepEqual(original.host.streams[0].events, [["write", [40, 41]], ["finish"]]);
  assert.equal(hosts.length, 2);
  assert.equal(calls.spawn.length, 2);
});

test("SDK-WT-CANCEL-KIND: session cancellation retains attribution across live and pending operations", { timeout: 5000 }, async (t) => {
  const { open, calls } = await fixture(t);
  const { session, host } = open();
  const stream = unwrap(await session.openStream());
  const reading = stream.read();
  const accepting = session.acceptUnidirectionalStream();
  await turn();
  const token = cancelled(session.cancel("navigation", "left the document"));
  for (const outcome of await Promise.all([reading, accepting, stream.closed])) {
    assert.deepEqual(clone(cancelled(outcome)), clone(token));
  }
  assert.equal(token.kind, "navigation");
  assert.equal(token.phase, "cancelling");
  assert.equal(token.message, "left the document");
  assertUnlocked(host.streams[0]);
  assert.equal(host.incomingUnidirectionalStreams.locked, false);
  assert.equal(closeCount(host), 1);
  assert.equal(calls.cancel.length, 1);
  assert.equal(calls.cancel[0].kind, "navigation");
  assert.equal(calls.join.length, 1);
});

for (const target of ["task-handle", "token-core-handle", "token-raw-reference"]) {
  test(`SDK-WT-GENERIC-CANCEL-${target}: generic task cancellation drains its SDK-owned session`, { timeout: 5000 }, async (t) => {
    const { sdk, open, calls } = await fixture(t);
    const { session, host } = open();
    const stream = unwrap(await session.openStream());
    const reading = stream.read();
    const accepting = session.acceptBidirectionalStream();
    await turn();
    assert.equal(host.incomingBidirectionalStreams.locked, true);
    const token = new sdk.CancellationToken("navigation", "generic owner cancelled");
    const outcome = target === "task-handle"
      ? new sdk.TaskHandle(session.core).cancel(token.kind, token.message)
      : token.cancel(target === "token-core-handle" ? session.core : session.toJSON());
    unwrap(outcome);
    for (const terminal of await Promise.all([reading, accepting, stream.closed])) {
      const result = cancelled(terminal);
      assert.equal(result.kind, token.kind);
      assert.equal(result.message, token.message);
      assert.equal(result.phase, "cancelling");
    }
    assertUnlocked(host.streams[0]);
    assert.equal(host.incomingBidirectionalStreams.locked, false);
    assert.equal(closeCount(host), 1);
    assert.equal(calls.cancel.length, 1);
    assert.equal(calls.join.length, 1);
    assertSameHandle(calls.cancel[0].task, session);
  });
}

test("SDK-WT-CANCEL-DENIED: rejected ABI cancellation leaves the SDK-owned session operational", { timeout: 5000 }, async (t) => {
  const failure = {
    outcome: "err",
    failure: { code: "capability_denied", recoverability: "permanent", message: "task cancellation denied" },
  };
  const { sdk, open, calls } = await fixture(t, { cancelResponse: JSON.stringify(failure) });
  const { session, host } = open();
  const stream = unwrap(await session.openStream());
  assert.deepEqual(clone(new sdk.TaskHandle(session.core).cancel("navigation")), failure);
  assert.equal(closeCount(host), 0);
  assert.equal(calls.join.length, 0);
  unwrap(await stream.write(new Uint8Array([50])));
  host.streams[0].input.enqueue(new Uint8Array([51]));
  assert.deepEqual(bytes(await stream.read()), [51]);
  host.streams[0].input.close();
  assert.equal(unwrap(await stream.read()).done, true);
  unwrap(await stream.finish());
  unwrap(await stream.closed);
  cancelled(session.close());
  assert.equal(closeCount(host), 1);
  assert.equal(calls.join.length, 1);
});

test("SDK-WT-DATAGRAM-EOF: datagram terminal delivery also drains owned reliable streams", { timeout: 5000 }, async (t) => {
  const { open, calls } = await fixture(t);
  const { session, host } = open();
  const stream = unwrap(await session.openStream());
  const reading = stream.read();
  const accepting = session.acceptUnidirectionalStream();
  const datagram = session.recvDatagram();
  await turn();
  assert.equal(host.datagrams.readable.locked, true);
  assert.equal(host.incomingUnidirectionalStreams.locked, true);
  host.datagramInput.close();
  const terminal = cancelled(await datagram);
  assert.equal(terminal.kind, "webtransport_close");
  assert.match(terminal.message, /end-of-stream/);
  for (const result of await Promise.all([reading, accepting, stream.closed])) {
    assert.deepEqual(clone(cancelled(result)), clone(terminal));
  }
  assertUnlocked(host.streams[0]);
  assert.equal(host.incomingUnidirectionalStreams.locked, false);
  assert.equal(calls.join.length, 1);
  const rejected = await session.openStream();
  assert.equal(rejected.outcome, "err");
  assert.equal(rejected.failure.code, "invalid_handle");
});
