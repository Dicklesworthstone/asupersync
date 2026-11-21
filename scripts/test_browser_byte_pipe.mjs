/**
 * Region-owned byte piping: actual TypeScript manager and native Node WHATWG
 * streams. Only task admission/cancellation/publication are explicit doubles.
 * node --unhandled-rejections=strict --experimental-vm-modules --test \
 *   scripts/test_browser_byte_pipe.mjs
 * No Rust rebuild, browser-engine execution or network delivery is claimed.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { createContext, SourceTextModule } from "node:vm";

const sourcePath = process.env.ASUPERSYNC_BROWSER_BYTE_PIPE_SOURCE
  ?? new URL("../packages/browser/src/byte-pipe.ts", import.meta.url);
const source = readFileSync(sourcePath, "utf8");
const genericSource = readFileSync(new URL("../packages/browser/src/stream-pipe.ts", import.meta.url), "utf8");
console.log(JSON.stringify({
  scenario_id: "owned-browser-byte-pipe-native-host",
  source_sha256: createHash("sha256").update(source).digest("hex"),
  generic_pipe_source_sha256: createHash("sha256").update(genericSource).digest("hex"),
  evidence_scope: "actual TypeScript manager, native WHATWG streams, explicit task-ABI doubles",
  no_claim: ["browser-engine execution", "Rust rebuild", "Rust executor dispatch", "network delivery"],
}));

const ok = value => ({ outcome: "ok", value });
const err = message => ({ outcome: "err", failure: {
  code: "compatibility_rejected", recoverability: "transient", message,
} });
const turn = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function value(outcome) {
  assert.equal(outcome.outcome, "ok", JSON.stringify(outcome));
  return outcome.value;
}
async function bounded(promise) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("native pipe operation did not settle")), 5000);
    })]);
  } finally { clearTimeout(timer); }
}
async function pending(promise) {
  let settled = false;
  void promise.then(() => { settled = true; }, () => { settled = true; });
  await turn();
  assert.equal(settled, false, "the operation remains owned while native work is pending");
}
const module = new SourceTextModule(stripTypeScriptTypes(source, { mode: "transform" }), {
  context: createContext({ ArrayBuffer, Uint8Array, DataView, setTimeout, clearTimeout, queueMicrotask }),
});
await module.link(() => assert.fail("byte pipe manager added a runtime dependency"));
await module.evaluate();
const api = module.namespace;
const genericModule = new SourceTextModule(stripTypeScriptTypes(genericSource, { mode: "transform" }), {
  context: createContext({}),
});
await genericModule.link(() => assert.fail("generic pipe manager added a runtime dependency"));
await genericModule.evaluate();
const genericApi = genericModule.namespace;

function fixture(t, faults = {}, globals = {}, endpoints = undefined) {
  const calls = { spawn: [], cancel: [], join: [] }, tasks = new Set(), handles = [], pairs = [], gates = [];
  const scopes = new Set(["region:1:1:PRIVATE_OWNER_TOKEN", "region:2:1:PRIVATE_OWNER_TOKEN"]);
  const closing = new Set();
  const host = {
    ReadableStream, WritableStream, ReadableStreamDefaultReader, WritableStreamDefaultWriter,
    AbortSignal, AbortController, EventTarget, ArrayBuffer, Uint8Array, DataView,
    setTimeout, clearTimeout, queueMicrotask, ...globals,
  };
  const manager = api.createBrowserBytePipeManager({
    globalObject: () => host,
    isTracked: key => scopes.has(key),
    isClosing: key => closing.has(key),
    endpoints,
  });
  const gate = () => { const result = deferred(); gates.push(result); return result; };
  function pair(options = {}) {
    const events = { reads: 0, writes: [], cancels: [], aborts: [], closes: 0 };
    let readController, writeController;
    const input = new ReadableStream({
      start(controller) { readController = controller; },
      pull(controller) {
        events.reads += 1;
        return options.pull?.(controller, events.reads);
      },
      cancel(reason) { events.cancels.push(reason); return options.cancel?.(reason); },
    }, { highWaterMark: 0 });
    const output = new WritableStream({
      start(controller) { writeController = controller; },
      write(chunk) { events.writes.push(chunk); return options.write?.(chunk, events.writes.length); },
      close() { events.closes += 1; return options.close?.(); },
      abort(reason) { events.aborts.push(reason); return options.abort?.(reason); },
    }, { highWaterMark: 1 });
    const result = { input, output, events, readController, writeController };
    pairs.push(result);
    return result;
  }
  function start(streams, options = {}, scope = "region:1:1:PRIVATE_OWNER_TOKEN") {
    const result = manager.start(scope, () => {
      calls.spawn.push(scope);
      if (faults.throwSpawn) throw new Error("PRIVATE_OWNER_TOKEN: admission threw");
      if (faults.refuseSpawn) return err("task admission refused");
      const key = `task:${calls.spawn.length}:1:PRIVATE_OWNER_TOKEN`;
      tasks.add(key);
      faults.onSpawn?.(key);
      return ok({ key,
        cancel(kind, message) {
          calls.cancel.push({ key, kind, message });
          faults.onCancel?.();
          if (faults.throwCancel) throw new Error("PRIVATE_OWNER_TOKEN: cancellation threw");
          if (faults.refuseCancel) return err("task cancellation refused");
          return ok(undefined);
        },
        join(outcome) {
          calls.join.push({ key, outcome });
          assert.equal(streams.input.locked, false, "source lock released before task publication");
          assert.equal(streams.output.locked, false, "destination lock released before task publication");
          faults.onJoin?.();
          if (faults.throwJoin) throw new Error("PRIVATE_OWNER_TOKEN: publication threw");
          if (faults.refuseJoin) return err("task publication refused");
          if (faults.malformedJoin) return { outcome: "ok", value: "not a unit receipt" };
          if (faults.inconsistentJoin) return ok(undefined);
          assert.equal(tasks.delete(key), true, "task published exactly once");
          return outcome;
        },
      });
    }, streams.input, streams.output, options);
    if (result.outcome === "ok") handles.push(result.value);
    return result;
  }
  t.after(async () => {
    for (const waiter of gates) waiter.resolve();
    for (const key of ["throwSpawn", "refuseSpawn", "throwCancel", "refuseCancel", "throwJoin", "refuseJoin", "malformedJoin", "inconsistentJoin"]) faults[key] = false;
    faults.onSpawn = faults.onCancel = faults.onJoin = undefined;
    await bounded(Promise.all(handles.map(handle => handle.retire("fixture cleanup"))));
  });
  return { manager, start, pair, gate, calls, tasks, handles, pairs, scopes, closing, host };
}

test("module import needs no stream host; unavailable host refuses without task admission", t => {
  const f = fixture(t, {}, { ReadableStream: undefined });
  const streams = f.pair();
  assert.equal(f.start(streams).outcome, "err");
  assert.equal(f.calls.spawn.length, 0);
  assert.equal(streams.input.locked, false);
  assert.equal(streams.output.locked, false);
});

for (const options of [null, 42, "invalid", [], { maxChunkBytes: 0 }, { maxChunkBytes: 16_777_217 },
  { maxChunkBytes: 1.5 }, { maxBytes: -1 }, { maxBytes: Infinity },
  { maxBytes: Number.MAX_SAFE_INTEGER + 1 }, { signal: {} }]) {
  test(`invalid options refuse before task admission (${JSON.stringify(options)})`, t => {
    const f = fixture(t), streams = f.pair();
    assert.equal(f.start(streams, options).outcome, "err");
    assert.equal(f.calls.spawn.length, 0);
    assert.equal(streams.input.locked, false);
    assert.equal(streams.output.locked, false);
    assert.equal(streams.events.reads, 0);
  });
}

for (const side of ["input", "output"]) test(`locked ${side} refuses before spawn, without trusting its own locked field`, t => {
  const f = fixture(t), streams = f.pair();
  const lock = side === "input" ? streams.input.getReader() : streams.output.getWriter();
  Object.defineProperty(streams[side], "locked", { value: false });
  assert.equal(f.start(streams).outcome, "err");
  assert.equal(f.calls.spawn.length, 0);
  lock.releaseLock();
});

test("already-aborted signal refuses before admission and leaves native endpoints caller-owned", t => {
  const f = fixture(t), streams = f.pair(), controller = new AbortController();
  controller.abort("already cancelled");
  assert.equal(f.start(streams, { signal: controller.signal }).outcome, "cancelled");
  assert.equal(f.calls.spawn.length, 0);
  assert.equal(streams.input.locked, false);
  assert.equal(streams.output.locked, false);
  assert.equal(streams.events.reads, 0);
});

test("spawn refusal leaves both stream locks and source bytes untouched", t => {
  const f = fixture(t, { refuseSpawn: true }), streams = f.pair();
  assert.equal(f.start(streams).outcome, "err");
  assert.equal(f.calls.spawn.length, 1);
  assert.equal(f.tasks.size, 0);
  assert.equal(streams.input.locked, false);
  assert.equal(streams.output.locked, false);
  assert.equal(streams.events.reads, 0);
});

for (const side of ["source", "destination"]) test(`acquired-then-thrown ${side} lock cannot be falsely retired`, async t => {
  const Constructor = side === "source" ? ReadableStream : WritableStream;
  const method = side === "source" ? "getReader" : "getWriter";
  const nativeAcquire = Constructor.prototype[method];
  const hostilePrototype = Object.create(Constructor.prototype);
  Object.defineProperty(hostilePrototype, "locked", Object.getOwnPropertyDescriptor(Constructor.prototype, "locked"));
  let lostLock;
  hostilePrototype[method] = function () {
    lostLock = Reflect.apply(nativeAcquire, this, []);
    throw new Error("PRIVATE_OWNER_TOKEN: host acquired the native lock and then threw");
  };
  const f = fixture(t, {}, { [side === "source" ? "ReadableStream" : "WritableStream"]: { prototype: hostilePrototype } });
  const streams = f.pair();
  Object.setPrototypeOf(side === "source" ? streams.input : streams.output, hostilePrototype);
  t.after(() => lostLock?.releaseLock());
  const handle = value(f.start(streams));
  const first = await bounded(handle.completed);
  assert.equal(first.outcome, "err");
  assert.ok(lostLock, "the hostile host actually acquired the native lock before throwing");
  assert.equal((side === "source" ? streams.input : streams.output).locked, true);
  assert.equal(f.tasks.size, 1);
  assert.equal(f.calls.join.length, 0);
  assert.equal((await bounded(handle.retire())).outcome, "err");
  assert.equal(f.tasks.size, 1);
  assert.equal(f.calls.join.length, 0);
  assert.doesNotMatch(JSON.stringify(first), /PRIVATE_OWNER_TOKEN/);
});

test("untracked and closing scopes refuse without task or host effects", t => {
  const f = fixture(t), streams = f.pair();
  assert.equal(f.start(streams, {}, "unknown").outcome, "err");
  f.closing.add("region:1:1:PRIVATE_OWNER_TOKEN");
  assert.equal(f.start(streams).outcome, "err");
  assert.equal(f.calls.spawn.length, 0);
  assert.equal(streams.events.reads, 0);
});

test("hostile option getters cannot bypass the ancestry fence or escape synchronously", t => {
  const f = fixture(t), streams = f.pair();
  assert.equal(f.start(streams, { get maxBytes() { throw new Error("PRIVATE_OWNER_TOKEN"); } }).outcome, "err");
  const result = f.start(streams, { get maxChunkBytes() {
    f.closing.add("region:1:1:PRIVATE_OWNER_TOKEN");
    return 1024;
  } });
  assert.equal(result.outcome, "err");
  assert.equal(f.calls.spawn.length, 0);
  assert.equal(streams.input.locked, false);
  assert.equal(streams.output.locked, false);
});

test("copies exact subviews in FIFO order, handles empty chunks, closes destination and retires once", async t => {
  const f = fixture(t), chunks = [Uint8Array.of(99, 2, 3, 99).subarray(1, 3), new Uint8Array(0), Uint8Array.of(5)];
  const streams = f.pair({ pull(controller, index) {
    if (index <= chunks.length) controller.enqueue(chunks[index - 1]);
    else controller.close();
  } });
  const handle = value(f.start(streams));
  assert.deepEqual({ ...value(await bounded(handle.completed)) }, { bytesWritten: 3, chunksWritten: 3 });
  assert.deepEqual(streams.events.writes.map(chunk => [...chunk]), [[2, 3], [], [5]]);
  assert.notEqual(streams.events.writes[0], chunks[0]);
  assert.equal(streams.events.writes[0].buffer.byteLength, 2, "only the admitted view is retained");
  assert.equal(streams.events.closes, 1);
  assert.equal(streams.events.cancels.length, 0);
  assert.equal(streams.events.aborts.length, 0);
  assert.deepEqual({ ...handle.progress() }, { bytesWritten: 3, chunksWritten: 3 });
  assert.equal((await handle.retire()).outcome, "ok");
  assert.equal(f.calls.join.length, 1);
  assert.equal(f.tasks.size, 0);
});

test("slow native writes apply backpressure before pulling another chunk and retain the admitted copy", async t => {
  const f = fixture(t), writeStarted = f.gate(), finishWrite = f.gate();
  const bytes = Uint8Array.of(7, 8);
  const streams = f.pair({
    pull(controller, index) {
      if (index === 1) controller.enqueue(bytes);
      else if (index === 2) controller.enqueue(Uint8Array.of(9));
      else controller.close();
    },
    write(_chunk, index) { if (index === 1) { writeStarted.resolve(); return finishWrite.promise; } },
  });
  const handle = value(f.start(streams));
  await bounded(writeStarted.promise);
  bytes.fill(0);
  await pending(handle.completed);
  assert.equal(streams.events.reads, 1, "no speculative second source read while a sink write is pending");
  assert.equal(streams.events.writes.length, 1);
  assert.deepEqual({ ...handle.progress() }, { bytesWritten: 0, chunksWritten: 0 });
  assert.equal(f.tasks.size, 1);
  finishWrite.resolve();
  assert.equal((await bounded(handle.completed)).outcome, "ok");
  assert.deepEqual(streams.events.writes.map(chunk => [...chunk]), [[7, 8], [9]]);
  assert.equal(f.calls.join.length, 1);
});

test("EOF does not publish success while native destination close is pending", async t => {
  const f = fixture(t), closeStarted = f.gate(), finishClose = f.gate();
  const streams = f.pair({ pull: controller => controller.close(), close() { closeStarted.resolve(); return finishClose.promise; } });
  const handle = value(f.start(streams, { maxBytes: 0 }));
  await bounded(closeStarted.promise);
  await pending(handle.completed);
  assert.equal(f.tasks.size, 1);
  assert.equal(f.calls.join.length, 0);
  finishClose.resolve();
  assert.deepEqual({ ...value(await bounded(handle.completed)) }, { bytesWritten: 0, chunksWritten: 0 });
  assert.equal(streams.output.locked, false);
});

test("cancel a witnessed pending read: start both cleanup sides and await their native receipts", async t => {
  const f = fixture(t), readStarted = f.gate(), sourceStop = f.gate(), sinkStop = f.gate();
  const sourceStarted = f.gate(), sinkStarted = f.gate();
  const streams = f.pair({
    pull() { readStarted.resolve(); },
    cancel() { sourceStarted.resolve(); return sourceStop.promise; },
    abort() { sinkStarted.resolve(); return sinkStop.promise; },
  });
  const handle = value(f.start(streams));
  await bounded(readStarted.promise);
  const stopped = handle.cancel("caller stopped transfer");
  await bounded(Promise.all([sourceStarted.promise, sinkStarted.promise]));
  await pending(stopped);
  await pending(handle.completed);
  assert.equal(f.tasks.size, 1);
  assert.equal(f.calls.join.length, 0);
  sourceStop.resolve();
  await pending(stopped);
  sinkStop.resolve();
  assert.equal((await bounded(stopped)).outcome, "ok", "cancellation returns independent successful retirement");
  assert.equal((await bounded(handle.completed)).outcome, "cancelled");
  assert.equal(streams.events.cancels.length, 1);
  assert.equal(streams.events.aborts.length, 1);
  assert.equal(streams.events.writes.length, 0);
  assert.equal(f.tasks.size, 0);
});

test("cancellation of a pending write cannot retire its task or start another write", async t => {
  const f = fixture(t), writeStarted = f.gate(), finishWrite = f.gate();
  const streams = f.pair({
    pull: controller => controller.enqueue(Uint8Array.of(1, 2)),
    write() { writeStarted.resolve(); return finishWrite.promise; },
  });
  const handle = value(f.start(streams));
  await bounded(writeStarted.promise);
  const stopped = handle.cancel("during host write");
  await pending(stopped);
  assert.equal(f.calls.join.length, 0);
  assert.equal(f.tasks.size, 1);
  assert.equal(streams.events.writes.length, 1);
  finishWrite.resolve();
  assert.equal((await bounded(stopped)).outcome, "ok");
  assert.equal((await bounded(handle.completed)).outcome, "cancelled");
  assert.equal(streams.events.writes.length, 1);
  assert.equal(streams.events.reads, 1);
  assert.equal(streams.events.aborts.length, 1);
  assert.equal(streams.input.locked, false);
  assert.equal(streams.output.locked, false);
});

test("cancel during native close waits for close and does not report transfer success", async t => {
  const f = fixture(t), closeStarted = f.gate(), finishClose = f.gate();
  const streams = f.pair({ pull: controller => controller.close(), close() { closeStarted.resolve(); return finishClose.promise; } });
  const handle = value(f.start(streams));
  await bounded(closeStarted.promise);
  const stopped = handle.cancel("cancel during close");
  await pending(stopped);
  assert.equal(f.calls.join.length, 0);
  finishClose.resolve();
  assert.equal((await bounded(stopped)).outcome, "ok");
  assert.equal((await bounded(handle.completed)).outcome, "cancelled");
  assert.equal(f.tasks.size, 0);
});

test("borrowed AbortSignal cancels a parked transfer without mutating caller signal", async t => {
  const f = fixture(t), readStarted = f.gate(), controller = new AbortController();
  const streams = f.pair({ pull() { readStarted.resolve(); } });
  const handle = value(f.start(streams, { signal: controller.signal }));
  await bounded(readStarted.promise);
  assert.equal(controller.signal.aborted, false);
  controller.abort("private caller reason");
  assert.equal((await bounded(handle.completed)).outcome, "cancelled");
  assert.equal(controller.signal.reason, "private caller reason");
  assert.equal((await handle.retire()).outcome, "ok");
  assert.equal(f.tasks.size, 0);
});

for (const [name, options, chunks, expected] of [
  ["chunk limit", { maxChunkBytes: 2 }, [Uint8Array.of(1, 2, 3)], []],
  ["total limit", { maxBytes: 4 }, [Uint8Array.of(1, 2), Uint8Array.of(3, 4, 5)], [[1, 2]]],
  ["zero total", { maxBytes: 0 }, [Uint8Array.of(1)], []],
]) test(`${name} refuses before the disallowed native write, preserving committed progress`, async t => {
  const f = fixture(t), streams = f.pair({ pull(controller, index) {
    if (index <= chunks.length) controller.enqueue(chunks[index - 1]);
    else controller.close();
  } });
  const handle = value(f.start(streams, options));
  assert.equal((await bounded(handle.completed)).outcome, "err");
  assert.deepEqual(streams.events.writes.map(chunk => [...chunk]), expected);
  assert.equal(handle.progress().bytesWritten, expected.flat().length);
  assert.equal(handle.progress().chunksWritten, expected.length);
  assert.equal(streams.events.closes, 0);
  assert.equal(streams.events.cancels.length, 1);
  assert.equal(streams.events.aborts.length, 1);
  assert.equal((await handle.retire()).outcome, "ok");
});

for (const [name, chunk] of [
  ["string", "bytes"], ["ArrayBuffer", new ArrayBuffer(2)],
  ["DataView", new DataView(new ArrayBuffer(2))], ["Uint16Array", new Uint16Array(1)],
]) test(`non-byte chunk ${name} fails without passing it to native sink`, async t => {
  const f = fixture(t), streams = f.pair({ pull: controller => controller.enqueue(chunk) });
  const handle = value(f.start(streams));
  assert.equal((await bounded(handle.completed)).outcome, "err");
  assert.equal(streams.events.writes.length, 0);
  assert.equal(handle.progress().bytesWritten, 0);
  assert.equal(f.tasks.size, 0);
});

test("chunk metadata and iterator shadows cannot change the copied byte range", async t => {
  const f = fixture(t), bytes = Uint8Array.of(9, 4, 5, 9).subarray(1, 3);
  for (const key of ["byteLength", "byteOffset", "buffer", "constructor", Symbol.iterator]) {
    Object.defineProperty(bytes, key, { get() { assert.fail("untrusted typed-array property evaluated"); } });
  }
  const streams = f.pair({ pull(controller, index) { if (index === 1) controller.enqueue(bytes); else controller.close(); } });
  const handle = value(f.start(streams));
  assert.equal((await bounded(handle.completed)).outcome, "ok");
  assert.deepEqual(streams.events.writes.map(chunk => [...chunk]), [[4, 5]]);
});

for (const kind of ["detached", "out-of-bounds"]) test(`${kind} Uint8Array is rejected rather than counted as an empty chunk`, async t => {
  const f = fixture(t);
  const buffer = new ArrayBuffer(8, { maxByteLength: 8 });
  const bytes = new Uint8Array(buffer, 4, 4);
  if (kind === "detached") structuredClone(buffer, { transfer: [buffer] });
  else buffer.resize(2);
  const streams = f.pair({ pull(controller, index) { if (index === 1) controller.enqueue(bytes); else controller.close(); } });
  const handle = value(f.start(streams));
  assert.equal((await bounded(handle.completed)).outcome, "err");
  assert.equal(streams.events.writes.length, 0);
  assert.equal(f.tasks.size, 0);
});

test("instance getReader/getWriter overrides cannot substitute foreign operations", async t => {
  const f = fixture(t), streams = f.pair({ pull: controller => controller.close() });
  streams.input.getReader = () => assert.fail("instance source method used");
  streams.output.getWriter = () => assert.fail("instance destination method used");
  const handle = value(f.start(streams));
  assert.equal((await bounded(handle.completed)).outcome, "ok");
});

test("source failure aborts the destination and publishes failure with no successful bytes", async t => {
  const f = fixture(t), streams = f.pair({ pull: controller => controller.error(new Error("source failed")) });
  const handle = value(f.start(streams));
  assert.equal((await bounded(handle.completed)).outcome, "err");
  assert.equal(streams.events.writes.length, 0);
  assert.equal(streams.events.aborts.length, 1);
  assert.equal(f.tasks.size, 0);
});

test("sink failure cancels the source without counting or duplicating the refused write", async t => {
  const f = fixture(t), streams = f.pair({
    pull: controller => controller.enqueue(Uint8Array.of(1, 2)),
    write() { throw new Error("sink refused write"); },
  });
  const handle = value(f.start(streams));
  assert.equal((await bounded(handle.completed)).outcome, "err");
  assert.equal(streams.events.writes.length, 1);
  assert.equal(streams.events.cancels.length, 1);
  assert.equal(handle.progress().bytesWritten, 0);
  assert.equal(f.tasks.size, 0);
});

test("an externally errored destination cancels a parked source read", async t => {
  const f = fixture(t), readStarted = f.gate();
  const streams = f.pair({ pull() { readStarted.resolve(); } });
  const handle = value(f.start(streams));
  await bounded(readStarted.promise);
  streams.writeController.error(new Error("destination became unusable"));
  assert.equal((await bounded(handle.completed)).outcome, "err");
  assert.equal(streams.events.cancels.length, 1);
  assert.equal(f.tasks.size, 0);
});

test("an externally errored source stops pulling while an already submitted native write drains", async t => {
  const f = fixture(t), writeStarted = f.gate(), finishWrite = f.gate();
  const streams = f.pair({
    pull: controller => controller.enqueue(Uint8Array.of(1)),
    write() { writeStarted.resolve(); return finishWrite.promise; },
  });
  const handle = value(f.start(streams));
  await bounded(writeStarted.promise);
  streams.readController.error(new Error("source became unusable"));
  await pending(handle.completed);
  assert.equal(f.calls.join.length, 0);
  finishWrite.resolve();
  assert.equal((await bounded(handle.completed)).outcome, "err");
  assert.equal(streams.events.reads, 1);
  assert.equal(streams.events.writes.length, 1);
  assert.equal(streams.events.aborts.length, 1);
  assert.equal(f.tasks.size, 0);
});

for (const failure of ["refuseCancel", "throwCancel"]) test(`${failure} retains task authority until explicit retirement retry`, async t => {
  const faults = { [failure]: true }, f = fixture(t, faults), readStarted = f.gate();
  const streams = f.pair({ pull() { readStarted.resolve(); } });
  const handle = value(f.start(streams));
  await bounded(readStarted.promise);
  assert.equal((await bounded(handle.cancel())).outcome, "err");
  assert.equal(f.tasks.size, 1);
  assert.equal(f.calls.join.length, 0);
  faults[failure] = false;
  assert.equal((await bounded(handle.retire())).outcome, "ok");
  assert.equal(f.tasks.size, 0);
  assert.equal(streams.events.cancels.length, 1);
  assert.equal(streams.events.aborts.length, 1);
});

for (const failure of ["refuseJoin", "throwJoin", "malformedJoin"]) test(`${failure} cannot manufacture success and retries publication without copying bytes twice`, async t => {
  const faults = { [failure]: true }, f = fixture(t, faults);
  const streams = f.pair({ pull(controller, index) { if (index === 1) controller.enqueue(Uint8Array.of(3)); else controller.close(); } });
  const handle = value(f.start(streams));
  const first = await bounded(handle.completed);
  assert.equal(first.outcome, "err");
  assert.equal(f.tasks.size, 1);
  assert.equal(streams.events.writes.length, 1);
  assert.doesNotMatch(JSON.stringify(first), /PRIVATE_OWNER_TOKEN/);
  faults[failure] = false;
  assert.equal((await bounded(handle.retire())).outcome, "ok");
  assert.equal(f.tasks.size, 0);
  assert.equal(streams.events.writes.length, 1);
  assert.equal(streams.events.closes, 1);
  assert.equal(await handle.completed, first, "first terminal receipt remains stable after independent retry");
});

test("inconsistent successful publication cannot erase operation failure", async t => {
  const faults = { inconsistentJoin: true }, f = fixture(t, faults);
  const streams = f.pair({ pull: controller => controller.error(new Error("operation failed")) });
  const handle = value(f.start(streams));
  assert.equal((await bounded(handle.completed)).outcome, "err");
  assert.equal(f.tasks.size, 1);
  faults.inconsistentJoin = false;
  assert.equal((await bounded(handle.retire())).outcome, "ok");
  assert.equal(f.tasks.size, 0);
});

for (const side of ["cancel", "abort"]) test(`a rejected native ${side} remains a retained cleanup failure across retries`, async t => {
  const f = fixture(t), readStarted = f.gate();
  const streams = f.pair({ pull() { readStarted.resolve(); }, [side]() { return Promise.reject(new Error("host cleanup rejected")); } });
  const handle = value(f.start(streams));
  await bounded(readStarted.promise);
  assert.equal((await bounded(handle.cancel())).outcome, "err");
  assert.equal((await bounded(handle.completed)).outcome, "err");
  assert.equal(f.tasks.size, 1);
  assert.equal(f.calls.join.length, 0);
  assert.equal((await bounded(handle.retire())).outcome, "err");
  assert.equal((await bounded(handle.retire())).outcome, "err");
  assert.equal(f.tasks.size, 1);
  assert.equal(f.calls.join.length, 0);
  assert.equal(streams.events.cancels.length, 1);
  assert.equal(streams.events.aborts.length, 1);
});

test("scope drain retires only the selected owner and preserves a sibling transfer", async t => {
  const f = fixture(t), firstRead = f.gate(), secondRead = f.gate();
  const first = f.pair({ pull() { firstRead.resolve(); } }), second = f.pair({ pull() { secondRead.resolve(); } });
  const a = value(f.start(first)), b = value(f.start(second, {}, "region:2:1:PRIVATE_OWNER_TOKEN"));
  await bounded(Promise.all([firstRead.promise, secondRead.promise]));
  assert.equal((await bounded(f.manager.drainScopes(new Set(["region:1:1:PRIVATE_OWNER_TOKEN"]), "scope_close"))).outcome, "ok");
  assert.equal((await bounded(a.completed)).outcome, "cancelled");
  await pending(b.completed);
  assert.equal(first.events.cancels.length, 1);
  assert.equal(second.events.cancels.length, 0);
  assert.equal(f.tasks.size, 1);
  assert.equal((await bounded(b.cancel())).outcome, "ok");
  assert.equal(f.tasks.size, 0);
});

for (const firstKind of ["byte", "generic"]) test(`${firstKind} pipe publication refusal retains endpoint exclusivity across both SDK managers`, async t => {
  const endpoints = new WeakSet(), faults = { refuseJoin: firstKind === "byte" };
  const f = fixture(t, faults, {}, endpoints);
  const genericTasks = new Set(), genericHandles = [];
  let genericSpawns = 0, refuseGenericJoin = firstKind === "generic";
  const genericManager = genericApi.createBrowserStreamPipeManager({
    globalObject: () => f.host, isTracked: key => f.scopes.has(key), isClosing: key => f.closing.has(key), endpoints,
  });
  const streams = f.pair({ pull(controller, index) { if (index === 1) controller.enqueue(Uint8Array.of(4)); else controller.close(); } });
  const startGeneric = () => {
    const result = genericManager.start("region:1:1:PRIVATE_OWNER_TOKEN", () => {
      const key = `generic:${++genericSpawns}`;
      genericTasks.add(key);
      return ok({ key, cancel: () => ok(undefined), join(outcome) {
        assert.equal(streams.input.locked || streams.output.locked, false);
        if (refuseGenericJoin) return err("generic task publication refused");
        assert.equal(genericTasks.delete(key), true);
        return outcome;
      } });
    }, streams.input, streams.output);
    if (result.outcome === "ok") genericHandles.push(result.value);
    return result;
  };
  t.after(async () => {
    refuseGenericJoin = false;
    await bounded(Promise.all(genericHandles.map(handle => handle.retire())));
  });
  const first = value(firstKind === "byte" ? f.start(streams) : startGeneric());
  assert.equal((await bounded(firstKind === "byte" ? first.completed : first.closed)).outcome, "err");
  assert.equal(streams.input.locked || streams.output.locked, false, "native lock release is not an accepted SDK task publication");
  assert.equal((firstKind === "byte" ? startGeneric() : f.start(streams)).outcome, "err");
  assert.equal(firstKind === "byte" ? genericSpawns : f.calls.spawn.length, 0, "other manager must refuse before allocating its task");
  faults.refuseJoin = false;
  refuseGenericJoin = false;
  assert.equal((await bounded(first.retire())).outcome, "ok");
  // New admission is now allowed. Native pipeTo accepts already-closed source
  // and destination; the byte pump's explicit writer.close refuses a second
  // close. Neither completion may replay a source chunk or reopen the sink.
  const next = value(firstKind === "byte" ? startGeneric() : f.start(streams));
  assert.equal((await bounded(firstKind === "byte" ? next.closed : next.completed)).outcome,
    firstKind === "byte" ? "ok" : "err");
  assert.equal((await bounded(next.retire())).outcome, "ok");
  assert.equal(streams.events.writes.length, 1);
  assert.equal(f.tasks.size + genericTasks.size, 0);
});

test("task cancellation bridges to native cleanup and repeated retirement cannot duplicate publication", async t => {
  const f = fixture(t), readStarted = f.gate(), streams = f.pair({ pull() { readStarted.resolve(); } });
  const handle = value(f.start(streams));
  await bounded(readStarted.promise);
  f.manager.cancelTask([...f.tasks][0], "external_task_cancel", "caller requested cancellation");
  assert.equal((await bounded(handle.completed)).outcome, "cancelled");
  assert.equal((await bounded(handle.retire())).outcome, "ok");
  assert.equal((await bounded(handle.cancel())).outcome, "ok");
  assert.equal(f.calls.join.length, 1);
  assert.equal(streams.events.cancels.length, 1);
  assert.equal(streams.events.aborts.length, 1);
});

test("synchronously ready empty chunks yield to a timer-triggered cancellation", async t => {
  const f = fixture(t), controller = new AbortController();
  const streams = f.pair({ pull(source, index) {
    // A finite fail-safe makes a missing event-loop yield observable without
    // letting the negative control itself freeze the whole test process.
    if (index > 10_000) throw new Error("pipe starved host timers");
    source.enqueue(new Uint8Array(0));
  } });
  const handle = value(f.start(streams, { signal: controller.signal }));
  const timer = setTimeout(() => controller.abort(), 0);
  t.after(() => clearTimeout(timer));
  assert.equal((await bounded(handle.completed)).outcome, "cancelled");
  assert.ok(streams.events.reads < 10_000, "host cancellation runs before the finite starvation guard");
  assert.equal(f.tasks.size, 0);
});
