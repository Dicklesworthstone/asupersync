/**
 * Bridge plan R33c: bounded WebTransport datagram admission and retention.
 * Run: node --experimental-vm-modules --test scripts/test_browser_webtransport_datagram_bounds.mjs
 * Set ASUPERSYNC_BROWSER_CORE_SOURCE to an old index.js for red/green replay.
 * Executes the actual JS facade against native WHATWG streams. The raw task
 * ABI and the unrelated reliable-stream manager are intentional call-recording
 * doubles. This is not evidence of WASM, Rust, live HTTP/3 or browser execution.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";

const sourcePath = process.env.ASUPERSYNC_BROWSER_CORE_SOURCE
  ?? fileURLToPath(new URL("../packages/browser-core/index.js", import.meta.url));
const source = readFileSync(sourcePath, "utf8");
const MAX_DATAGRAM = 65_536;
const MAX_COUNT = 256;
const MAX_BYTES = 1_048_576;
const turn = () => new Promise((resolve) => setImmediate(resolve));
console.log(JSON.stringify({
  plan: "R33c", source_sha256: createHash("sha256").update(source).digest("hex"),
  evidence_scope: "JS datagram facade with native WHATWG streams and explicit ABI/sibling doubles",
}));

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

async function fixture(t, options = {}) {
  const calls = { joins: [], cancels: [], streamCloses: [] };
  let host;
  let nextTask = 1;
  const unit = '{"outcome":"ok","value":{"kind":"unit"}}';
  class Host {
    constructor() {
      host = this;
      this.events = [];
      this.handshake = deferred();
      this.ready = this.handshake.promise;
      this.completion = deferred();
      this.closed = this.completion.promise;
      this.datagrams = {
        maxDatagramSize: options.maxDatagramSize ?? MAX_DATAGRAM,
        readable: new ReadableStream({
          start: (controller) => { this.input = controller; },
          cancel: (reason) => { this.events.push(["cancel", reason]); },
        }, { highWaterMark: 0 }),
        writable: new WritableStream({
          write: (bytes) => {
            this.events.push(["write", Uint8Array.from(bytes)]);
            return options.write?.(bytes);
          },
          close: () => { this.events.push(["writer-close"]); },
        }),
      };
      if (!options.pendingHandshake) this.handshake.resolve();
    }
    close(info = {}) {
      this.events.push(["close", info.reason]);
      this.completion.resolve(info);
    }
  }
  const context = createContext({
    ArrayBuffer, Uint8Array, URL, TextEncoder: options.TextEncoder ?? TextEncoder,
    Error, TypeError, RangeError,
    WebTransport: Host,
  });
  const functions = {
    default: () => {},
    runtime_create: () => '{"kind":"runtime","slot":0,"generation":1,"owner_token":"42"}',
    scope_enter: () => '{"kind":"region","slot":1,"generation":1,"owner_token":"42"}',
    runtime_close: () => unit,
    scope_close: () => unit,
    task_spawn: () => JSON.stringify({ kind: "task", slot: nextTask++, generation: 1, owner_token: "42" }),
    task_join: (_handle, outcome) => { calls.joins.push(JSON.parse(outcome)); return outcome; },
    task_cancel: (request) => { calls.cancels.push(JSON.parse(request)); return unit; },
  };
  for (const name of ["abi_fingerprint", "abi_version", "fetch_request", "websocket_cancel",
    "websocket_close", "websocket_open", "websocket_recv", "websocket_send"]) {
    functions[name] = () => { throw new Error(`Unexpected ABI call ${name}`); };
  }
  const bindings = new SyntheticModule(Object.keys(functions), function () {
    for (const [name, fn] of Object.entries(functions)) this.setExport(name, fn);
  }, { context });
  const streams = new SyntheticModule(["createReliableStreamManager", "WEBTRANSPORT_STREAM_LIMITS"], function () {
    this.setExport("WEBTRANSPORT_STREAM_LIMITS", Object.freeze({}));
    this.setExport("createReliableStreamManager", () => ({
      closeSession: (_state, outcome) => { calls.streamCloses.push(outcome); },
    }));
  }, { context });
  const module = new SourceTextModule(`${source}\nexport { INFLIGHT_WEBTRANSPORTS as hostSessions };`, {
    context, identifier: sourcePath,
  });
  await module.link((specifier) => {
    if (specifier === "./webtransport-streams.js") return streams;
    assert.equal(specifier, "./asupersync.js");
    return bindings;
  });
  await module.evaluate();
  const core = module.namespace;
  const runtime = core.runtime_create().value;
  const scope = core.scope_enter({ parent: runtime }).value;
  const opened = core.webtransport_open({ scope, url: "https://transport.example.test/" });
  assert.equal(opened.outcome, "ok");
  const session = opened.value;
  const state = [...core.hostSessions.values()][0];
  t.after(async () => { core.scope_close(scope); await turn(); });
  await turn();
  return {
    core, scope, session, host, calls, state,
    recv: () => core.webtransport_recv({ session }),
    send: (value) => core.webtransport_send({ session, value }),
  };
}

function assertTerminal(f, pattern) {
  const outcome = f.recv();
  assert.equal(outcome.outcome, "err");
  assert.match(outcome.failure.message, pattern);
  assert.equal(f.calls.joins.length, 1, "the runtime task is joined exactly once");
  assert.equal(f.calls.streamCloses.length, 1, "session closure reaches its reliable streams");
  assert.equal(f.core.hostSessions.size, 0, "terminal receive releases retained session");
  assert.equal(f.recv().failure.code, "invalid_handle");
}

function assertBytes(outcome, bytes) {
  assert.equal(outcome.outcome, "ok");
  assert.deepEqual(Array.from(outcome.value), bytes);
}

test("WT-RX count cap includes empty datagrams and reserves one terminal slot", async (t) => {
  const f = await fixture(t);
  for (let i = 0; i < MAX_COUNT; i += 1) f.host.input.enqueue(new Uint8Array());
  await turn();
  assert.equal(f.state.inbox.length, MAX_COUNT);
  f.host.input.enqueue(new Uint8Array());
  await turn();
  assert.equal(f.state.closed, true);
  assert.equal(f.state.inbox.length, MAX_COUNT + 1);
  for (let i = 0; i < MAX_COUNT; i += 1) assertBytes(f.recv(), []);
  assertTerminal(f, /receive queue capacity exhausted/);
});

test("WT-RX byte cap preserves every accepted datagram in FIFO order", async (t) => {
  const f = await fixture(t);
  const count = MAX_BYTES / MAX_DATAGRAM;
  for (let i = 0; i < count; i += 1) f.host.input.enqueue(new Uint8Array(MAX_DATAGRAM).fill(i));
  await turn();
  assert.equal(f.state.inboxBytes, MAX_BYTES);
  f.host.input.enqueue(Uint8Array.of(99));
  await turn();
  assert.equal(f.state.closed, true);
  assert.equal(f.state.inboxBytes, MAX_BYTES);
  for (let i = 0; i < count; i += 1) {
    const outcome = f.recv();
    assert.equal(outcome.outcome, "ok");
    assert.equal(outcome.value.byteLength, MAX_DATAGRAM);
    assert.equal(outcome.value.every((byte) => byte === i), true);
  }
  assert.equal(f.state.inboxBytes, 0);
  assertTerminal(f, /receive queue capacity exhausted/);
});

test("WT-RX receiving replenishes both count and byte capacity", async (t) => {
  const f = await fixture(t);
  for (let i = 0; i < MAX_BYTES / MAX_DATAGRAM; i += 1) f.host.input.enqueue(new Uint8Array(MAX_DATAGRAM));
  await turn();
  assert.equal(f.recv().value.byteLength, MAX_DATAGRAM);
  f.host.input.enqueue(new Uint8Array(MAX_DATAGRAM).fill(7));
  await turn();
  assert.equal(f.state.closed, false);
  assert.equal(f.state.inboxBytes, MAX_BYTES);
  while (f.recv().value !== undefined) {}
  for (let i = 0; i < MAX_COUNT; i += 1) f.host.input.enqueue(new Uint8Array());
  await turn();
  assertBytes(f.recv(), []);
  f.host.input.enqueue(new Uint8Array());
  await turn();
  assert.equal(f.state.inbox.length, MAX_COUNT);
  assert.equal(f.state.closed, false);
});

test("WT-RX oversized input is rejected before reading array elements", async (t) => {
  const f = await fixture(t);
  const oversized = new Array(MAX_DATAGRAM + 1);
  let reads = 0;
  Object.defineProperty(oversized, 0, { get() { reads += 1; return 0; } });
  f.host.input.enqueue(Uint8Array.of(1, 2));
  f.host.input.enqueue(oversized);
  await turn();
  assert.equal(reads, 0);
  assertBytes(f.recv(), [1, 2]);
  assertTerminal(f, /datagram byte limit/);
});

test("WT-RX copies only the admitted view and does not retain its backing buffer", async (t) => {
  const f = await fixture(t);
  const backing = new Uint8Array(MAX_BYTES * 2);
  const view = backing.subarray(123, 126);
  view.set([3, 5, 8]);
  f.host.input.enqueue(view);
  await turn();
  view.fill(0);
  const outcome = f.recv();
  assertBytes(outcome, [3, 5, 8]);
  assert.equal(outcome.value.buffer.byteLength, 3);
});

test("WT-RX EOF behind a full inbox preserves the terminal outcome", async (t) => {
  const f = await fixture(t);
  for (let i = 0; i < MAX_COUNT; i += 1) f.host.input.enqueue(new Uint8Array());
  f.host.input.close();
  await turn();
  assert.equal(f.calls.joins.length, 1);
  for (let i = 0; i < MAX_COUNT; i += 1) assertBytes(f.recv(), []);
  assert.equal(f.recv().outcome, "cancelled");
  assert.equal(f.core.hostSessions.size, 0);
});

test("WT-RX sparse input cannot fabricate zero bytes", async (t) => {
  const f = await fixture(t);
  f.host.input.enqueue(new Array(2));
  await turn();
  assertTerminal(f, /integer bytes/);
});

test("WT-RX owner close during input normalization cannot retain a late datagram", async (t) => {
  const f = await fixture(t);
  const input = [1];
  Object.defineProperty(input, 0, { get() { f.core.scope_close(f.scope); return 1; } });
  f.host.input.enqueue(input);
  await turn();
  assert.equal(f.state.closed, true);
  assert.equal(f.state.inbox.length, 0);
  assert.equal(f.core.hostSessions.size, 0);
  assert.equal(f.calls.joins.length, 0, "owner closure, not a second task join, owns retirement");
});

function assertSendCapacity(outcome) {
  assert.equal(outcome.outcome, "err");
  assert.equal(outcome.failure.code, "compatibility_rejected");
  assert.equal(outcome.failure.recoverability, "transient");
  assert.match(outcome.failure.message, /send queue capacity exhausted/);
}

function assertSendReleased(f) {
  assert.equal(f.state.pendingWrites.length, 0);
  assert.equal(f.state.pendingWriteCount, 0);
  assert.equal(f.state.pendingWriteBytes, 0);
}

test("WT-TX pending readiness is bounded even for empty datagrams", async (t) => {
  const f = await fixture(t, { pendingHandshake: true });
  for (let i = 0; i < MAX_COUNT; i += 1) assert.equal(f.send([]).outcome, "ok");
  assertSendCapacity(f.send([]));
  assert.equal(f.state.pendingWrites.length, MAX_COUNT);
  assert.equal(f.state.pendingWriteCount, MAX_COUNT);
  assert.equal(f.state.pendingWriteBytes, 0);
  assert.equal(f.state.closed, false, "backpressure must not close the session");
  f.core.scope_close(f.scope);
  assertSendReleased(f);
  f.host.handshake.resolve();
  await turn();
  assert.equal(f.host.events.some(([kind]) => kind === "write"), false);
});

test("WT-TX parked write counts against byte capacity and completion permits retry", async (t) => {
  const parked = deferred();
  let writes = 0;
  const f = await fixture(t, { write: () => ++writes === 1 ? parked.promise : undefined });
  const count = MAX_BYTES / MAX_DATAGRAM;
  assert.equal(f.send(new Uint8Array(MAX_DATAGRAM).fill(0)).outcome, "ok");
  await turn();
  assert.equal(writes, 1, "the host write is parked before filling the remaining budget");
  for (let i = 1; i < count; i += 1) {
    assert.equal(f.send(new Uint8Array(MAX_DATAGRAM).fill(i)).outcome, "ok");
  }
  assertSendCapacity(f.send([99]));
  assert.equal(f.state.pendingWrites.length, count - 1);
  assert.equal(f.state.pendingWriteCount, count);
  assert.equal(f.state.pendingWriteBytes, MAX_BYTES);
  parked.resolve();
  await turn();
  assertSendReleased(f);
  assert.equal(f.send([99]).outcome, "ok");
  await turn();
  assertSendReleased(f);
  assert.deepEqual(
    f.host.events.filter(([kind]) => kind === "write").map(([, bytes]) => bytes[0]),
    [...Array.from({ length: count }, (_, i) => i), 99],
    "accepted datagrams retain FIFO order; a refused send was never written",
  );
});

test("WT-TX parked empty write counts against the datagram count cap", async (t) => {
  const parked = deferred();
  const f = await fixture(t, { write: () => parked.promise });
  assert.equal(f.send([]).outcome, "ok");
  await turn();
  assert.equal(f.host.events.filter(([kind]) => kind === "write").length, 1);
  for (let i = 1; i < MAX_COUNT; i += 1) assert.equal(f.send([]).outcome, "ok");
  assertSendCapacity(f.send([]));
  assert.equal(f.state.pendingWrites.length, MAX_COUNT - 1);
  assert.equal(f.state.pendingWriteCount, MAX_COUNT);
  f.core.scope_close(f.scope);
  assertSendReleased(f);
  parked.resolve();
  await turn();
  assertSendReleased(f);
  assert.equal(f.host.events.filter(([kind]) => kind === "write").length, 1);
  assert.equal(f.calls.joins.length, 0, "late host completion cannot join a closed owner's task");
});

test("WT-TX oversized bytes and UTF-8 strings are refused before copying or encoding", async (t) => {
  let encodes = 0;
  class RecordingEncoder extends TextEncoder {
    encode(value) { encodes += 1; return super.encode(value); }
  }
  const f = await fixture(t, { pendingHandshake: true, TextEncoder: RecordingEncoder });
  let reads = 0;
  const array = new Array(MAX_DATAGRAM + 1);
  Object.defineProperty(array, 0, { get() { reads += 1; return 1; } });
  for (const value of [array, new Uint8Array(MAX_DATAGRAM + 1),
    new ArrayBuffer(MAX_DATAGRAM + 1), new DataView(new ArrayBuffer(MAX_DATAGRAM + 1)),
    "x".repeat(MAX_DATAGRAM + 1), "\u00e9".repeat(MAX_DATAGRAM / 2 + 1),
    "\ud83d\ude00".repeat(MAX_DATAGRAM / 4 + 1)]) {
    const outcome = f.send(value);
    assert.equal(outcome.outcome, "err");
    assert.equal(outcome.failure.recoverability, "permanent");
    assert.match(outcome.failure.message, /datagram byte limit/);
  }
  assert.equal(reads, 0);
  assert.equal(encodes, 0, "oversized UTF-8 is refused before TextEncoder allocates");
  assertSendReleased(f);
  const boundary = "\ud83d\ude00".repeat(MAX_DATAGRAM / 4);
  assert.equal(f.send(boundary).outcome, "ok");
  assert.equal(f.state.pendingWriteBytes, MAX_DATAGRAM);
  assert.equal(encodes, 1);
  const mixed = "a\u00e9\u20ac\ud800z\udc00\ud83d\ude00";
  assert.equal(f.send(mixed).outcome, "ok");
  assert.equal(f.state.pendingWriteBytes, MAX_DATAGRAM + new TextEncoder().encode(mixed).byteLength);
  assert.deepEqual(Array.from(f.state.pendingWrites[1]), Array.from(new TextEncoder().encode(mixed)));
});

test("WT-TX byte capacity is checked before input element access or encoding", async (t) => {
  let encodes = 0;
  class RecordingEncoder extends TextEncoder {
    encode(value) { encodes += 1; return super.encode(value); }
  }
  const f = await fixture(t, { pendingHandshake: true, TextEncoder: RecordingEncoder });
  for (let i = 0; i < MAX_BYTES / MAX_DATAGRAM; i += 1) {
    assert.equal(f.send(new Uint8Array(MAX_DATAGRAM)).outcome, "ok");
  }
  let reads = 0;
  const input = [1];
  Object.defineProperty(input, 0, { get() { reads += 1; return 1; } });
  assertSendCapacity(f.send(input));
  assertSendCapacity(f.send("x"));
  assert.equal(reads, 0);
  assert.equal(encodes, 0);
  assert.equal(f.state.pendingWriteBytes, MAX_BYTES);
});

test("WT-TX reserves admission before reentrant input access and rolls back invalid bytes", async (t) => {
  const f = await fixture(t, { pendingHandshake: true });
  for (let i = 0; i < MAX_COUNT - 1; i += 1) assert.equal(f.send([]).outcome, "ok");
  let nested;
  const input = [1];
  Object.defineProperty(input, 0, { get() { nested = f.send([]); return 1; } });
  assert.equal(f.send(input).outcome, "ok");
  assertSendCapacity(nested);
  assert.equal(f.state.pendingWriteCount, MAX_COUNT);
  assert.equal(f.state.pendingWriteBytes, 1);

  const g = await fixture(t, { pendingHandshake: true });
  for (const invalid of [[256], [-1], [1.5], new Array(1)]) {
    assert.equal(g.send(invalid).outcome, "err");
    assertSendReleased(g);
  }
  assert.equal(g.send([42]).outcome, "ok");
  assert.equal(g.state.pendingWriteBytes, 1);
});

test("WT-TX copies only admitted subviews and ignores arbitrary array iterators", async (t) => {
  const f = await fixture(t, { pendingHandshake: true });
  const backing = new Uint8Array(MAX_BYTES * 2);
  const view = backing.subarray(123, 126);
  view.set([3, 5, 8]);
  assert.equal(f.send(view).outcome, "ok");
  view.fill(0);
  assert.equal(f.state.pendingWrites[0].buffer.byteLength, 3);
  assert.deepEqual(Array.from(f.state.pendingWrites[0]), [3, 5, 8]);
  const input = [1, 2];
  input[Symbol.iterator] = () => { throw new Error("unbounded iterator must not run"); };
  assert.equal(f.send(input).outcome, "ok");
  assert.deepEqual(Array.from(f.state.pendingWrites[1]), [1, 2]);
});

test("WT-TX owner close during input copying refuses late data and clears reservations", async (t) => {
  const f = await fixture(t, { pendingHandshake: true });
  const input = [1];
  Object.defineProperty(input, 0, { get() { f.core.scope_close(f.scope); return 1; } });
  const result = f.send(input);
  assert.equal(result.outcome, "err");
  assert.equal(result.failure.code, "invalid_handle");
  assertSendReleased(f);
  assert.equal(f.core.hostSessions.size, 0);
});

test("WT-TX failed host write releases queued capacity and joins exactly once", async (t) => {
  const parked = deferred();
  const f = await fixture(t, { write: () => parked.promise });
  assert.equal(f.send([1, 2]).outcome, "ok");
  await turn();
  assert.equal(f.send([3]).outcome, "ok");
  parked.reject(new Error("host rejected the datagram"));
  await turn();
  assertSendReleased(f);
  assertTerminal(f, /datagram write failed: host rejected the datagram/);
  assert.equal(f.host.events.filter(([kind]) => kind === "write").length, 1);
});

test("WT-TX owner close during host write lookup prevents a late host call", async (t) => {
  const f = await fixture(t);
  const writer = f.state.writer;
  const write = writer.write;
  Object.defineProperty(writer, "write", {
    get() {
      f.core.scope_close(f.scope);
      return write;
    },
  });
  assert.equal(f.send([7]).outcome, "ok");
  await turn();
  assertSendReleased(f);
  assert.equal(f.host.events.some(([kind]) => kind === "write"), false);
  assert.equal(f.calls.joins.length, 0);
});
