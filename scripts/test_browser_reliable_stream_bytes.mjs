/** Execute the reliable-stream byte boundary with native WHATWG streams.
 * No WASM, browser engine, or live HTTP/3 conformance is claimed here.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { runInNewContext } from "node:vm";

const sourcePath = process.env.ASUPERSYNC_RELIABLE_STREAM_SOURCE
  ?? new URL("../packages/browser-core/webtransport-streams.js", import.meta.url);
const source = await readFile(sourcePath, "utf8");
console.log(JSON.stringify({
  scenario_id: "browser-reliable-stream-byte-boundary",
  bead_id: "br-asupersync-bi2462.133",
  source_sha256: createHash("sha256").update(source).digest("hex"),
  evidence_scope: "reliable-stream JS module and native WHATWG streams; no WASM or live HTTP/3",
}));
const { createReliableStreamManager, WEBTRANSPORT_STREAM_LIMITS } = await import(
  `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`,
);
const ok = (value) => ({ outcome: "ok", value });
const fail = (code, recoverability, message) => ({ outcome: "err", failure: { code, recoverability, message } });
const cancelled = (message, origin) => ({ outcome: "cancelled", cancellation: { message, origin } });

async function fixture(t, { chunk, onWrite } = {}) {
  const writes = [];
  const cleanup = { read: 0, write: 0 };
  const readable = new ReadableStream({
    start(controller) { if (chunk !== undefined) controller.enqueue(chunk); },
    cancel() { cleanup.read += 1; },
  }, { highWaterMark: 0 });
  const writable = new WritableStream({
    async write(bytes) {
      writes.push(bytes);
      await onWrite?.(bytes);
    },
    abort() { cleanup.write += 1; },
  });
  const state = { closed: false, sessionOrigin: "byte-boundary", transport: {
    ready: Promise.resolve(),
    createBidirectionalStream: async () => ({ readable, writable }),
  } };
  const manager = createReliableStreamManager({ lookup: () => state, ok, fail, cancelled });
  t.after(async () => {
    await manager.closeSessionAndDrain(state, cancelled("test cleanup", "byte-boundary"));
    assert.equal(readable.locked, false);
    assert.equal(writable.locked, false);
  });
  const result = await manager.open({ session: "session" });
  assert.equal(result.outcome, "ok");
  return { stream: result.value, writes, cleanup, manager, state, readable, writable };
}

for (const [name, make] of [
  ["local Uint8Array", () => new Uint8Array([1, 2, 3])],
  ["local ArrayBuffer", () => new Uint8Array([1, 2, 3]).buffer],
  ["local DataView window", () => new DataView(new Uint8Array([9, 1, 2, 3, 9]).buffer, 1, 3)],
  ["foreign Uint8Array", () => runInNewContext("new Uint8Array([1, 2, 3])")],
  ["foreign ArrayBuffer", () => runInNewContext("new Uint8Array([1, 2, 3]).buffer")],
  ["foreign DataView window", () => runInNewContext("new DataView(new Uint8Array([9, 1, 2, 3, 9]).buffer, 1, 3)")],
  ["empty ArrayBuffer", () => new ArrayBuffer(0)],
]) {
  test(`write accepts the actual bytes of ${name}`, { timeout: 3000 }, async (t) => {
    const { stream, writes } = await fixture(t);
    assert.equal((await stream.write(make())).outcome, "ok");
    assert.deepEqual(Array.from(writes[0]), name.startsWith("empty") ? [] : [1, 2, 3]);
  });
}

for (const name of ["buffer", "byteOffset", "byteLength"]) {
  for (const kind of ["typed array", "DataView"]) {
    test(`write never invokes an overridden ${kind} ${name}`, { timeout: 3000 }, async (t) => {
      const { stream, writes } = await fixture(t);
      const storage = new Uint8Array([9, 1, 2, 3, 9]);
      const value = kind === "typed array" ? storage.subarray(1, 4) : new DataView(storage.buffer, 1, 3);
      let calls = 0;
      Object.defineProperty(value, name, { get() { calls += 1; throw new Error("untrusted metadata getter"); } });
      const result = await stream.write(value);
      assert.equal(calls, 0, "metadata admission must not call user code");
      assert.equal(result.outcome, "ok");
      assert.deepEqual(Array.from(writes[0]), [1, 2, 3]);
    });
  }
}

test("oversized actual bytes cannot be hidden behind a forged byteLength", { timeout: 3000 }, async (t) => {
  const { stream, writes } = await fixture(t);
  const value = new Uint8Array(WEBTRANSPORT_STREAM_LIMITS.maxWriteBytes + 1);
  Object.defineProperty(value, "byteLength", { value: 1 });
  const result = await stream.write(value);
  assert.equal(result.outcome, "err");
  assert.equal(result.failure.recoverability, "permanent");
  assert.match(result.failure.message, /maxWriteBytes/);
  assert.equal(writes.length, 0);
  assert.equal((await stream.write(new Uint8Array([7]))).outcome, "ok", "refusal releases admission");
});

test("forged backing cannot trigger iterable allocation before the size check", { timeout: 3000 }, async (t) => {
  const { stream, writes } = await fixture(t);
  const value = new Uint8Array([1, 2, 3]);
  let iterations = 0;
  Object.defineProperty(value, "buffer", { value: {
    *[Symbol.iterator]() { iterations += 1; yield 99; },
  } });
  assert.equal((await stream.write(value)).outcome, "ok");
  assert.equal(iterations, 0, "never construct a view from caller-supplied backing metadata");
  assert.deepEqual(Array.from(writes[0]), [1, 2, 3]);
});

test("write snapshots bytes before host backpressure and rejects a competing write", { timeout: 3000 }, async (t) => {
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  const { stream, writes } = await fixture(t, { onWrite: () => held });
  const value = new Uint8Array([1, 2, 3]);
  const pending = stream.write(value);
  value.fill(9);
  const competing = await stream.write(new Uint8Array([4]));
  assert.equal(competing.outcome, "err");
  assert.equal(competing.failure.recoverability, "transient");
  release();
  assert.equal((await pending).outcome, "ok");
  assert.deepEqual(Array.from(writes[0]), [1, 2, 3]);
});

for (const kind of ["ArrayBuffer", "Uint8Array", "DataView"]) {
  test(`detached ${kind} is refused without poisoning the stream`, { timeout: 3000 }, async (t) => {
    const { stream, writes } = await fixture(t);
    const buffer = new ArrayBuffer(3);
    const value = kind === "ArrayBuffer" ? buffer : kind === "DataView" ? new DataView(buffer) : new Uint8Array(buffer);
    structuredClone(buffer, { transfer: [buffer] });
    assert.equal((await stream.write(value)).outcome, "err");
    assert.equal(writes.length, 0);
    assert.equal((await stream.write(new Uint8Array([1]))).outcome, "ok");
  });
}

test("out-of-bounds resizable typed array is not silently accepted as an empty write", { timeout: 3000 }, async (t) => {
  const { stream, writes } = await fixture(t);
  const buffer = new ArrayBuffer(8, { maxByteLength: 16 });
  const value = new Uint8Array(buffer, 4, 4);
  buffer.resize(2);
  assert.equal((await stream.write(value)).outcome, "err");
  assert.equal(writes.length, 0);
  buffer.resize(8);
  assert.equal((await stream.write(value)).outcome, "ok");
});

test("foreign response bytes remain readable across browser realms", { timeout: 3000 }, async (t) => {
  const chunk = runInNewContext("new Uint8Array([1, 2, 3])");
  const { stream } = await fixture(t, { chunk });
  const result = await stream.read();
  assert.equal(result.outcome, "ok");
  assert.equal(result.value.done, false);
  assert.equal(result.value.value, chunk, "preserve the existing zero-copy read contract");
});

for (const [name, make] of [
  ["prototype impostor", () => Object.create(Uint8Array.prototype)],
  ["tag impostor", () => ({ [Symbol.toStringTag]: "Uint8Array" })],
  ["non-byte typed array", () => new Uint16Array([1, 2])],
]) {
  test(`read rejects a ${name} and drains both halves`, { timeout: 3000 }, async (t) => {
    const { stream, cleanup } = await fixture(t, { chunk: make() });
    const result = await stream.read();
    assert.equal(result.outcome, "err");
    assert.match(result.failure.message, /non-byte chunk/);
    assert.equal(await stream.closed, result);
    assert.deepEqual(cleanup, { read: 1, write: 1 });
  });
}

test("receive brand validation ignores an overridden toStringTag", { timeout: 3000 }, async (t) => {
  const chunk = new Uint8Array([1, 2, 3]);
  Object.defineProperty(chunk, Symbol.toStringTag, { get() { throw new Error("untrusted tag"); } });
  const { stream } = await fixture(t, { chunk });
  assert.equal((await stream.read()).outcome, "ok");
});
