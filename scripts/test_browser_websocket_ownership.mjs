/** Actual owned-WebSocket TypeScript, native EventTarget/Streams, and a real
 * Node WebSocket peer. Task receipts in focused cases are explicit doubles.
 * node --experimental-vm-modules --test scripts/test_browser_websocket_ownership.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { getEventListeners } from "node:events";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { createContext, SourceTextModule } from "node:vm";

const source = readFileSync(process.env.ASUPERSYNC_BROWSER_WEBSOCKET_SOURCE
  ?? new URL("../packages/browser/src/websocket.ts", import.meta.url), "utf8");
console.log(JSON.stringify({ scenario: "owned-browser-websocket", source_sha256: createHash("sha256").update(source).digest("hex"),
  evidence: "actual manager; native EventTarget/Streams and real Node WebSocket/HTTP-upgrade peer; explicit task receipts" }));
const ok = value => ({ outcome: "ok", value });
const err = message => ({ outcome: "err", failure: { code: "compatibility_rejected", recoverability: "transient", message } });
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
async function pending(promise) { let settled = false; void promise.then(() => { settled = true; }, () => { settled = true; }); await turn(); assert.equal(settled, false); }
function value(outcome) { assert.equal(outcome.outcome, "ok", JSON.stringify(outcome)); return outcome.value; }
function noListeners(socket) { for (const type of ["open", "message", "error", "close"]) assert.equal(getEventListeners(socket, type).length, 0, `${type} listeners retired`); }
async function load() {
  // Absence of host WebSocket/AbortSignal/MessageEvent at module import is valid.
  const module = new SourceTextModule(stripTypeScriptTypes(source, { mode: "transform" }), { context: createContext({}) });
  await module.link(() => assert.fail("WebSocket manager added a runtime dependency"));
  await module.evaluate(); return module.namespace;
}
const api = await load();

class FaultTarget extends EventTarget {
  addEventListener(type, listener, options) {
    if (this.fault?.refuseAddBefore === type) throw new Error("private pre-attach detail");
    super.addEventListener(type, listener, options);
    this.fault?.afterAdd?.(type);
    if (this.fault?.refuseAdd === type) throw new Error("private attach detail");
  }
  removeEventListener(type, listener, options) {
    if (this.fault?.refuseRemove === type) throw new Error("private detach detail");
    super.removeEventListener(type, listener, options);
  }
}
class Socket extends FaultTarget {
  constructor(fault = {}) { super(); this.fault = fault; this.state = fault.state ?? 0; this.buffered = 0; this.binary = "blob"; this.sent = []; this.closes = []; }
  get readyState() { return this.state; }
  get bufferedAmount() { this.fault.onBuffered?.(); return this.buffered; }
  get protocol() { return "test.v1"; }
  get extensions() { return ""; }
  get binaryType() { return this.binary; }
  set binaryType(value) { this.binary = value; }
  send(value) { this.sent.push(value); }
  close(code, reason) {
    this.closes.push({ code, reason });
    if (this.fault.refuseClose) throw new Error("private close detail");
    if (this.state < 2) this.state = 2;
    if (this.fault.autoClose) queueMicrotask(() => this.finish());
  }
  open() { this.state = 1; this.dispatchEvent(new Event("open")); }
  message(data) { this.dispatchEvent(new MessageEvent("message", { data })); }
  finish(clean = true) {
    this.state = 3;
    const event = new Event("close");
    Object.defineProperties(event, { wasClean: { value: clean }, code: { value: clean ? 1000 : 1006 } });
    this.dispatchEvent(event);
  }
  fail() { this.dispatchEvent(new Event("error")); }
}
function fixture(t, faults = {}, globals = {}) {
  const calls = { spawn: [], cancel: [], join: [] }, tasks = new Set(), sockets = [], handles = [];
  const scopes = new Set(["region:1:1:PRIVATE_AUTHORITY", "region:2:1:PRIVATE_AUTHORITY"]), closing = new Set();
  const host = { WebSocket: Socket, EventTarget: FaultTarget, MessageEvent, AbortSignal, ReadableStream, ...globals };
  const manager = api.createBrowserWebSocketManager({ globalObject: () => host,
    isTracked: key => scopes.has(key), isClosing: key => closing.has(key) });
  function adopt(socket = new Socket(), options = {}, scope = "region:1:1:PRIVATE_AUTHORITY") {
    if (!sockets.includes(socket)) sockets.push(socket);
    const result = manager.adopt(scope, () => {
      calls.spawn.push(scope);
      if (faults.refuseSpawn) return err("task admission refused");
      const key = `task:${calls.spawn.length}:1:PRIVATE_AUTHORITY`;
      tasks.add(key);
      faults.onSpawn?.();
      return ok({ key, cancel(kind, message) {
        calls.cancel.push({ key, kind, message });
        faults.onCancel?.();
        if (faults.throwCancel) throw new Error("private ABI cancellation detail");
        return faults.refuseCancel ? err("task cancellation refused") : ok(undefined);
      }, join(outcome) {
        calls.join.push({ key, outcome });
        assert.equal(socket.readyState, 3, "native close precedes task join");
        noListeners(socket);
        faults.onJoin?.();
        if (faults.throwJoin) throw new Error("private ABI publication detail");
        if (faults.refuseJoin) return err("task publication refused");
        if (faults.inconsistentJoin) return ok(undefined);
        assert.equal(tasks.delete(key), true, "task is published exactly once");
        return outcome;
      } });
    }, socket, options);
    if (result.outcome === "ok") handles.push(result.value);
    return result;
  }
  t.after(async () => {
    for (const socket of sockets) {
      socket.fault ??= {};
      socket.fault.refuseClose = false; socket.fault.refuseRemove = undefined; socket.fault.refuseAdd = undefined;
      socket.fault.refuseAddBefore = undefined;
      if (socket instanceof Socket && socket.state !== 3) socket.finish();
    }
    faults.refuseCancel = faults.throwCancel = faults.refuseJoin = faults.throwJoin = faults.inconsistentJoin = false;
    await Promise.all(handles.map(handle => handle.retire("fixture cleanup")));
  });
  return { manager, adopt, calls, tasks, scopes, closing, host };
}

test("module import needs no WebSocket globals; unavailable adoption has no effects", t => {
  const f = fixture(t, {}, { WebSocket: undefined });
  assert.equal(f.adopt(new Socket()).outcome, "err"); assert.equal(f.calls.spawn.length, 0);
});
for (const options of [null, { maxQueuedMessages: 0 }, { maxQueuedMessages: 4097 }, { maxQueuedBytes: Infinity },
  { maxMessageBytes: -1 }, { maxSendBufferedBytes: 0 }, { signal: {} }]) {
  test(`invalid options refuse before task admission (${JSON.stringify(options)})`, t => {
    const f = fixture(t), socket = new Socket();
    assert.equal(f.adopt(socket, options).outcome, "err");
    assert.equal(f.calls.spawn.length, 0); assert.equal(socket.binaryType, "blob"); assert.equal(socket.closes.length, 0); noListeners(socket);
  });
}
for (const state of [2, 3]) test(`a socket already in state ${state} stays caller-owned`, t => {
  const f = fixture(t), socket = new Socket({ state });
  assert.equal(f.adopt(socket).outcome, "err"); assert.equal(f.calls.spawn.length, 0); noListeners(socket);
});
test("adoption is exclusive across scopes and task refusal does not take the socket", async t => {
  const faults = { refuseSpawn: true }, f = fixture(t, faults), socket = new Socket();
  assert.equal(f.adopt(socket).outcome, "err"); noListeners(socket); assert.equal(socket.binary, "blob");
  faults.refuseSpawn = false; value(f.adopt(socket));
  assert.equal(f.adopt(socket, {}, "region:2:1:PRIVATE_AUTHORITY").outcome, "err");
  assert.equal(f.calls.spawn.length, 2); assert.equal(socket.binary, "arraybuffer");
});
test("opened waits for native open, and text/binary/empty messages retain FIFO order", async t => {
  const f = fixture(t), socket = new Socket(), handle = value(f.adopt(socket));
  await pending(handle.opened); socket.open(); assert.equal(value(await handle.opened).protocol, "test.v1");
  const binary = Uint8Array.of(1, 2, 3);
  socket.message("hello"); socket.message(binary.buffer); socket.message(""); binary[0] = 99;
  assert.equal(value(await handle.receive()).value, "hello");
  assert.deepEqual(Array.from(value(await handle.receive()).value), [1, 2, 3]);
  assert.equal(value(await handle.receive()).value, "");
  socket.finish(); assert.equal((await handle.closed).outcome, "ok"); assert.equal(value(await handle.receive()).done, true);
  assert.equal(f.calls.cancel.length, 0); assert.equal(f.calls.join.length, 1);
});
test("only one receive may be pending; an excess receive does not steal its message", async t => {
  const f = fixture(t), socket = new Socket({ state: 1 }), handle = value(f.adopt(socket));
  const first = handle.receive(); await pending(first);
  assert.equal((await handle.receive()).outcome, "err"); socket.message("first"); assert.equal(value(await first).value, "first");
  const second = handle.receive(); socket.message("second"); assert.equal(value(await second).value, "second");
});
test("manual cancellation fences ingress and awaits actual close before cleanup/task join", async t => {
  const f = fixture(t), socket = new Socket({ state: 1 }), handle = value(f.adopt(socket));
  const read = handle.receive(), stopped = handle.cancel("consumer stopped");
  await pending(stopped); await pending(read); assert.equal(socket.closes.length, 1); assert.equal(f.calls.join.length, 0);
  assert.equal(f.tasks.size, 1); socket.message("late"); socket.finish();
  assert.equal((await stopped).outcome, "cancelled"); assert.equal((await read).outcome, "cancelled");
  assert.equal((await handle.retire()).outcome, "ok"); assert.equal(f.tasks.size, 0); noListeners(socket);
  assert.doesNotMatch(JSON.stringify({ closed: await handle.closed, opened: await handle.opened, closes: socket.closes }), /PRIVATE_AUTHORITY/);
});
test("native conversion is memoized and exclusive, and refuses a pending manual read", async t => {
  const f = fixture(t), socket = new Socket({ state: 1 }), handle = value(f.adopt(socket));
  const read = handle.receive(); assert.equal(handle.toReadableStream().outcome, "err");
  socket.message("manual"); await read;
  const stream = value(handle.toReadableStream()); assert.equal(value(handle.toReadableStream()), stream);
  assert.equal((await handle.receive()).outcome, "err");
  const reader = stream.getReader(), next = reader.read(); socket.message("stream"); assert.equal((await next).value, "stream");
  reader.releaseLock();
});
test("a final message racing native close is delivered before stream EOF", async t => {
  const f = fixture(t), socket = new Socket({ state: 1 }), handle = value(f.adopt(socket));
  const reader = value(handle.toReadableStream()).getReader(), next = reader.read();
  socket.message("last"); socket.finish();
  assert.deepEqual(await next, { value: "last", done: false }); assert.equal((await reader.read()).done, true);
  assert.equal((await handle.closed).outcome, "ok"); reader.releaseLock();
});
test("normal remote close preserves unread queued messages without retaining the task", async t => {
  const f = fixture(t), socket = new Socket({ state: 1 }), handle = value(f.adopt(socket));
  socket.message("a"); socket.message("b"); socket.finish();
  assert.equal((await handle.closed).outcome, "ok"); assert.equal(f.tasks.size, 0);
  assert.equal(value(await handle.receive()).value, "a"); assert.equal(value(await handle.receive()).value, "b");
  assert.equal(value(await handle.receive()).done, true);
});
for (const [name, options, messages] of [
  ["message count", { maxQueuedMessages: 2 }, ["", "", ""]],
  ["UTF-8 bytes", { maxQueuedBytes: 4 }, ["é", "é", "x"]],
  ["surrogate pair bytes", { maxQueuedBytes: 3 }, ["😀"]],
  ["single message", { maxMessageBytes: 2 }, ["abc"]],
  ["binary bytes", { maxQueuedBytes: 3 }, [Uint8Array.of(1, 2).buffer, Uint8Array.of(3, 4).buffer]],
]) test(`${name} overflow stops the socket and surfaces a typed failure after close`, async t => {
  const f = fixture(t), socket = new Socket({ state: 1 }), handle = value(f.adopt(socket, options));
  for (const message of messages) socket.message(message);
  await turn(); assert.equal(socket.closes.length, 1); assert.equal(f.calls.join.length, 0);
  socket.finish(); const terminal = await handle.closed;
  assert.equal(terminal.outcome, "err"); assert.match(terminal.failure.message, /buffer limit/);
  assert.equal((await handle.receive()).outcome, "err"); assert.equal((await handle.retire()).outcome, "ok");
});
test("consumption returns byte/count credit, and unsupported Blob messages fail without conversion work", async t => {
  const f = fixture(t), socket = new Socket({ state: 1 }), handle = value(f.adopt(socket, { maxQueuedMessages: 1, maxQueuedBytes: 2 }));
  socket.message("é"); await handle.receive(); socket.message("é"); assert.equal(value(await handle.receive()).value, "é");
  socket.message(new Blob(["hidden"])); await turn(); socket.finish();
  assert.match((await handle.closed).failure.message, /unsupported/);
});
test("send checks native state, exact UTF-8 bytes, typed-array subviews and native buffering", async t => {
  const f = fixture(t), socket = new Socket(), handle = value(f.adopt(socket, { maxMessageBytes: 4, maxSendBufferedBytes: 5 }));
  assert.equal(handle.send("x").outcome, "err"); socket.open();
  assert.equal(handle.send("😀").outcome, "ok"); socket.buffered = 2;
  assert.equal(handle.send("😀").outcome, "err"); assert.equal(handle.send("abc").outcome, "ok");
  const bytes = Uint8Array.of(1, 2, 3, 4, 5).subarray(1, 4);
  Object.defineProperty(bytes, "byteLength", { value: 0 });
  assert.equal(handle.send(bytes).outcome, "ok"); assert.equal(socket.sent.at(-1), bytes);
  socket.buffered = 3; assert.equal(handle.send(bytes).outcome, "err");
  assert.equal(handle.send({ toString() { assert.fail("must not stringify"); } }).outcome, "err");
  assert.equal(socket.sent.length, 3);
});
test("send rechecks a close reentered from a native buffering observation", async t => {
  const socket = new Socket({ state: 1 }), f = fixture(t), handle = value(f.adopt(socket));
  socket.fault.onBuffered = () => { void handle.cancel(); };
  assert.equal(handle.send("late").outcome, "err"); assert.equal(socket.sent.length, 0);
});
test("graceful close validates code/reason then waits for the clean handshake", async t => {
  const f = fixture(t), socket = new Socket({ state: 1 }), handle = value(f.adopt(socket));
  assert.equal((await handle.close({ code: 1009 })).outcome, "err");
  assert.equal((await handle.close({ reason: "😀".repeat(31) })).outcome, "err"); assert.equal(socket.closes.length, 0);
  const closed = handle.close({ code: 4000, reason: "finished" }); await pending(closed);
  assert.deepEqual(socket.closes, [{ code: 4000, reason: "finished" }]); assert.equal(f.calls.cancel.length, 0);
  socket.finish(); assert.equal((await closed).outcome, "ok");
});
test("abnormal closure cannot turn a graceful close request into successful completion", async t => {
  const f = fixture(t), socket = new Socket({ state: 1 }), handle = value(f.adopt(socket));
  const closed = handle.close(); await turn(); socket.finish(false);
  assert.equal((await closed).outcome, "err"); assert.equal(f.calls.join[0].outcome.outcome, "err");
});
test("cancellation during graceful close discards queued messages and strengthens the terminal", async t => {
  const f = fixture(t), socket = new Socket({ state: 1 }), handle = value(f.adopt(socket));
  socket.message("discarded"); const closing = handle.close(); await pending(closing);
  const cancellation = handle.cancel("stop graceful close"); await pending(cancellation);
  assert.equal(socket.closes.length, 1); socket.finish();
  assert.equal((await cancellation).outcome, "cancelled"); assert.equal((await closing).outcome, "cancelled");
  assert.equal((await handle.receive()).outcome, "cancelled"); assert.equal(f.calls.cancel.length, 1);
});
test("cancelling completed receive ownership discards unread output without rewriting closed", async t => {
  const f = fixture(t), socket = new Socket({ state: 1 }), handle = value(f.adopt(socket));
  socket.message("discarded"); socket.finish(); assert.equal((await handle.closed).outcome, "ok");
  assert.equal((await handle.cancel()).outcome, "ok"); assert.equal(value(await handle.receive()).done, true);
});
test("error and close before open settle both waiters with sanitized failure", async t => {
  const f = fixture(t), socket = new Socket(), handle = value(f.adopt(socket));
  socket.fail(); await turn(); socket.finish(false);
  assert.equal((await handle.opened).outcome, "err"); assert.equal((await handle.closed).outcome, "err");
  assert.match((await handle.closed).failure.message, /transport failed/);
});
test("parent cancellation cannot be suppressed by an earlier listener and preserves caller ownership", async t => {
  const f = fixture(t), parent = new AbortController(), socket = new Socket({ state: 1 });
  parent.signal.addEventListener("abort", event => event.stopImmediatePropagation());
  const handle = value(f.adopt(socket, { signal: parent.signal })); parent.abort({ toString() { assert.fail("reason must not be formatted"); } });
  await turn(); assert.equal(socket.closes.length, 1); socket.finish();
  assert.equal((await handle.closed).cancellation.kind, "websocket_signal");
});
test("pre-aborted parent transfers ownership then closes without publishing an open socket", async t => {
  const f = fixture(t), parent = new AbortController(), socket = new Socket({ state: 1 }); parent.abort();
  const handle = value(f.adopt(socket, { signal: parent.signal }));
  assert.equal((await handle.opened).outcome, "cancelled"); await turn(); socket.finish();
  assert.equal((await handle.closed).outcome, "cancelled");
});
for (const fault of ["refuseCancel", "throwCancel", "refuseJoin", "throwJoin", "inconsistentJoin"]) {
  test(`${fault} retains ownership and explicit retirement retries after host close`, async t => {
    const faults = { [fault]: true }, f = fixture(t, faults), socket = new Socket({ state: 1 }), handle = value(f.adopt(socket));
    const cancelled = handle.cancel("stop"); await turn();
    assert.equal(socket.closes.length, 1, "even a thrown ABI cancellation must close the host");
    assert.equal(f.calls.join.length, 0); socket.finish(); assert.equal((await cancelled).outcome, "err");
    assert.equal(f.tasks.size, 1); assert.equal(f.adopt(socket).outcome, "err");
    faults[fault] = false; assert.equal((await handle.retire()).outcome, "ok"); assert.equal(f.tasks.size, 0);
    assert.equal(socket.closes.length, 1); assert.equal((await handle.closed).outcome, "err", "first receipt remains stable");
  });
}
test("native close refusal returns failure without releasing the task; retry joins actual close", async t => {
  const socket = new Socket({ state: 1, refuseClose: true }), f = fixture(t), handle = value(f.adopt(socket));
  assert.equal((await handle.cancel()).outcome, "err"); assert.equal(f.tasks.size, 1); await pending(handle.closed);
  socket.fault.refuseClose = false; const retry = handle.retire(); await pending(retry); socket.finish();
  assert.equal((await retry).outcome, "ok"); assert.equal(f.calls.cancel.length, 1); assert.equal(f.calls.join.length, 1);
});
test("listener cleanup refusal keeps the ledger task until a successful explicit retry", async t => {
  const socket = new Socket({ state: 1, refuseRemove: "message" }), f = fixture(t), handle = value(f.adopt(socket));
  const cancelled = handle.cancel(); await turn(); socket.finish(); assert.equal((await cancelled).outcome, "err");
  assert.equal(f.calls.join.length, 0); assert.equal(f.tasks.size, 1);
  socket.fault.refuseRemove = undefined; assert.equal((await handle.retire()).outcome, "ok"); noListeners(socket);
});
for (const fault of ["refuseAddBefore", "refuseAdd"]) {
  test(`${fault} close observation retains ownership and an explicit retry recovers`, async t => {
    const socket = new Socket({ state: 1, [fault]: "close" }), f = fixture(t), handle = value(f.adopt(socket));
    assert.equal((await handle.opened).outcome, "err");
    assert.equal((await handle.retire()).outcome, "err");
    assert.equal(socket.closes.length, 1); assert.equal(f.calls.join.length, 0); assert.equal(f.tasks.size, 1);
    socket.fault[fault] = undefined;
    const retried = handle.retire(); await pending(retried); socket.finish();
    assert.equal((await retried).outcome, "ok"); assert.equal((await handle.closed).outcome, "err");
    assert.match((await handle.closed).failure.message, /activation/); noListeners(socket);
  });
}
test("a missed close event is recovered only from positive native CLOSED state", async t => {
  const socket = new Socket({ state: 1, refuseAddBefore: "close" }), f = fixture(t), handle = value(f.adopt(socket));
  assert.equal((await handle.retire()).outcome, "err"); assert.equal(socket.readyState, 2); assert.equal(f.calls.join.length, 0);
  socket.finish(); assert.equal(f.calls.join.length, 0, "no listener observed this event");
  assert.equal((await handle.retire()).outcome, "ok"); assert.equal(f.tasks.size, 0); noListeners(socket);
});
test("native close during listener installation still detaches every later-installed hook", async t => {
  const socket = new Socket({ state: 1 }), f = fixture(t);
  socket.fault.afterAdd = type => { if (type === "close") socket.finish(); };
  const handle = value(f.adopt(socket)); assert.equal((await handle.closed).outcome, "ok");
  assert.equal((await handle.opened).outcome, "err"); noListeners(socket); assert.equal(f.calls.join.length, 1);
});
test("owner drain starts every close before waiting and retains the slow owner", async t => {
  const f = fixture(t), a = new Socket({ state: 1 }), b = new Socket({ state: 1 });
  value(f.adopt(a)); value(f.adopt(b, {}, "region:2:1:PRIVATE_AUTHORITY"));
  const drain = f.manager.drainScopes(f.scopes, "runtime_close"); await pending(drain);
  assert.equal(a.closes.length, 1); assert.equal(b.closes.length, 1); a.finish(); await pending(drain);
  assert.equal(f.tasks.size, 1); b.finish(); assert.equal((await drain).outcome, "ok"); assert.equal(f.tasks.size, 0);
});
test("external TaskHandle cancellation forwards without repeating ABI admission", async t => {
  const f = fixture(t), socket = new Socket({ state: 1 }), handle = value(f.adopt(socket));
  f.manager.cancelTask("task:1:1:PRIVATE_AUTHORITY", "owner_cancel", "external stop"); await turn(); socket.finish();
  assert.equal((await handle.closed).cancellation.kind, "owner_cancel"); assert.equal(f.calls.cancel.length, 0); assert.equal(f.calls.join.length, 1);
});
test("scope closure reentered during task admission fences activation", async t => {
  const faults = {}, f = fixture(t, faults), socket = new Socket({ state: 1 });
  faults.onSpawn = () => f.closing.add("region:1:1:PRIVATE_AUTHORITY");
  const handle = value(f.adopt(socket)); assert.equal((await handle.opened).outcome, "cancelled");
  assert.equal(handle.send("late").outcome, "err"); await turn(); socket.finish(); await handle.closed;
});
test("native iterator exit is a cleanup barrier and never repeats close", async t => {
  const f = fixture(t), socket = new Socket({ state: 1 }), handle = value(f.adopt(socket));
  const stream = value(handle.toReadableStream());
  const iterator = (async () => { for await (const message of stream) { assert.equal(message, "one"); break; } })();
  socket.message("one"); await pending(iterator); assert.equal(socket.closes.length, 1); assert.equal(f.calls.join.length, 0);
  socket.finish(); await iterator; assert.equal((await handle.closed).outcome, "cancelled");
  await handle.retire(); assert.equal(socket.closes.length, 1);
});
test("native stream cancellation exposes retained task failure through a sanitized Outcome cause", async t => {
  const faults = { refuseJoin: true }, f = fixture(t, faults), socket = new Socket({ state: 1 }), handle = value(f.adopt(socket));
  const cancelled = value(handle.toReadableStream()).cancel();
  const observed = assert.rejects(cancelled, error => {
    assert.equal(error.cause.outcome, "err"); assert.match(error.cause.failure.message, /publication refused/);
    assert.doesNotMatch(JSON.stringify(error.cause), /PRIVATE_AUTHORITY/); return true;
  });
  await turn(); socket.finish(); await observed; assert.equal(f.tasks.size, 1);
  faults.refuseJoin = false; assert.equal((await handle.retire()).outcome, "ok");
});

// Minimal independent server peer: receives client frames and deliberately
// withholds its close response to witness the real transport cleanup barrier.
async function peer(t) {
  const connected = deferred(), closing = deferred(), disconnected = deferred();
  const server = createServer(); let socket, input = Buffer.alloc(0); const received = [];
  function frame(opcode, payload = Buffer.alloc(0)) {
    assert.ok(payload.length < 126); return Buffer.concat([Buffer.from([0x80 | opcode, payload.length]), payload]);
  }
  server.on("upgrade", (request, client, head) => {
    socket = client;
    const accept = createHash("sha1").update(`${request.headers["sec-websocket-key"]}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest("base64");
    client.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    client.on("close", () => disconnected.resolve()); client.on("error", () => {});
    const consume = chunk => {
      input = Buffer.concat([input, chunk]);
      while (input.length >= 2) {
        const length = input[1] & 127; assert.ok(length < 126);
        const masked = (input[1] & 128) !== 0, offset = masked ? 6 : 2;
        if (input.length < offset + length) return;
        const opcode = input[0] & 15, payload = Buffer.from(input.subarray(offset, offset + length));
        if (masked) for (let i = 0; i < payload.length; i += 1) payload[i] ^= input[2 + i % 4];
        input = input.subarray(offset + length); received.push({ opcode, payload });
        if (opcode === 8) closing.resolve(payload);
      }
    };
    client.on("data", consume); if (head.length) consume(head); connected.resolve();
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { socket?.destroy(); await new Promise(resolve => server.close(resolve)); });
  return { url: `ws://127.0.0.1:${server.address().port}`, connected: connected.promise, closing: closing.promise,
    disconnected: disconnected.promise, received,
    send: value => socket.write(frame(typeof value === "string" ? 1 : 2, Buffer.from(value))),
    finish: async () => { const payload = await closing.promise; socket.end(frame(8, payload)); },
  };
}
test("real native WebSocket exchanges exact messages and joins only after peer close response", { timeout: 5000 }, async t => {
  const remote = await peer(t), socket = new WebSocket(remote.url), calls = [], manager = api.createBrowserWebSocketManager({
    globalObject: () => ({ WebSocket, EventTarget, MessageEvent, AbortSignal, ReadableStream }), isTracked: () => true, isClosing: () => false,
  });
  const handle = value(manager.adopt("region:real:PRIVATE_AUTHORITY", () => ok({ key: "task:real", cancel: () => ok(undefined),
    join: outcome => { calls.push(outcome); assert.equal(socket.readyState, WebSocket.CLOSED); noListeners(socket); return outcome; } }), socket));
  t.after(() => handle.retire());
  assert.equal((await handle.opened).outcome, "ok"); await remote.connected;
  assert.equal(handle.send("outbound").outcome, "ok");
  remote.send("héllo"); remote.send(Uint8Array.of(0, 255, 7));
  assert.equal(value(await handle.receive()).value, "héllo"); assert.deepEqual(Array.from(value(await handle.receive()).value), [0, 255, 7]);
  const closed = handle.close(); await remote.closing; await pending(closed); assert.equal(calls.length, 0);
  await remote.finish(); assert.equal((await closed).outcome, "ok"); await remote.disconnected;
  assert.equal(calls.length, 1); assert.equal(remote.received.find(message => message.opcode === 1).payload.toString(), "outbound");
});
