/**
 * Actual region-owned pipe manager with native WHATWG streams and explicit
 * task-admission/terminal-publication doubles. This is host-boundary evidence,
 * not a browser-engine run or Rust/WASM execution.
 * node --unhandled-rejections=strict --experimental-vm-modules --test scripts/test_browser_stream_pipe.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { getEventListeners } from "node:events";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { createContext, SourceTextModule } from "node:vm";

const source = readFileSync(process.env.ASUPERSYNC_BROWSER_STREAM_PIPE_SOURCE
  ?? new URL("../packages/browser/src/stream-pipe.ts", import.meta.url), "utf8");
console.log(JSON.stringify({
  scenario_id: "browser-region-owned-stream-pipe",
  source_sha256: createHash("sha256").update(source).digest("hex"),
  evidence_scope: "actual manager; native WHATWG streams; explicit task receipts",
  no_claim: ["browser-engine execution", "Rust/WASM execution", "arbitrary-chunk byte bounds"],
}));
const ok = value => ({ outcome: "ok", value });
const err = message => ({ outcome: "err", failure: {
  code: "compatibility_rejected", recoverability: "transient", message,
} });
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
const turn = () => new Promise(resolve => setImmediate(resolve));
const readLocked = Object.getOwnPropertyDescriptor(ReadableStream.prototype, "locked").get;
const writeLocked = Object.getOwnPropertyDescriptor(WritableStream.prototype, "locked").get;
const unlocked = (readable, writable) => {
  assert.equal(Reflect.apply(readLocked, readable, []), false, "reader lock released");
  assert.equal(Reflect.apply(writeLocked, writable, []), false, "writer lock released");
};
function value(outcome) {
  assert.equal(outcome.outcome, "ok", JSON.stringify(outcome));
  return outcome.value;
}
async function bounded(promise) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("owned pipe did not settle")), 1500);
    })]);
  } finally { clearTimeout(timer); }
}
async function pending(promise) {
  let settled = false;
  void promise.then(() => { settled = true; }, () => { settled = true; });
  await turn();
  assert.equal(settled, false, "completion must wait for native cleanup");
}
async function load() {
  // Import must remain safe when no browser stream globals exist.
  const module = new SourceTextModule(stripTypeScriptTypes(source, { mode: "transform" }),
    { context: createContext({}) });
  await module.link(() => assert.fail("pipe manager added a runtime dependency"));
  await module.evaluate();
  return module.namespace;
}
const api = await load();

function fixture(t, faults = {}, globals = {}) {
  const calls = { spawn: [], cancel: [], join: [] }, tasks = new Set(), handles = [], releases = [];
  const scopes = new Set(["owner", "sibling"]), closing = new Set();
  const host = { ReadableStream, WritableStream, AbortController, AbortSignal, EventTarget, ...globals };
  const manager = api.createBrowserStreamPipeManager({
    globalObject: () => host, isTracked: key => scopes.has(key), isClosing: key => closing.has(key),
  });
  function start(readable, writable, options = {}, scope = "owner") {
    const result = manager.start(scope, () => {
      calls.spawn.push(scope);
      if (faults.refuseSpawn) return err("task admission refused");
      const key = "task:" + calls.spawn.length + ":PRIVATE_AUTHORITY";
      tasks.add(key);
      faults.onSpawn?.(key);
      return ok({
        key,
        cancel(kind, message) {
          calls.cancel.push({ key, kind, message });
          faults.onCancel?.();
          if (faults.throwCancel) throw new Error("private cancellation detail");
          return faults.refuseCancel ? err("task cancellation refused") : ok(undefined);
        },
        join(outcome) {
          calls.join.push({ key, outcome });
          unlocked(readable, writable);
          faults.onJoin?.();
          if (faults.throwJoin) throw new Error("private publication detail");
          if (faults.refuseJoin) return err("task publication refused");
          if (faults.inconsistentJoin) return ok(undefined);
          assert.equal(tasks.delete(key), true, "a task is retired exactly once");
          return outcome;
        },
      });
    }, readable, writable, options);
    if (result.outcome === "ok") handles.push(result.value);
    return result;
  }
  t.after(async () => {
    for (const release of releases) release();
    faults.refuseCancel = faults.throwCancel = faults.refuseJoin = faults.throwJoin = faults.inconsistentJoin = false;
    faults.onCancel = faults.onJoin = undefined;
    await bounded(Promise.all(handles.map(handle => handle.retire("fixture cleanup"))));
  });
  return { manager, start, calls, tasks, handles, releases, scopes, closing, host };
}

function parked(source = {}, sink = {}) {
  return {
    readable: new ReadableStream(source, { highWaterMark: 0 }),
    writable: new WritableStream(sink),
  };
}

test("module import needs no stream globals; missing host support refuses before admission", t => {
  const f = fixture(t, {}, { WritableStream: undefined });
  const { readable, writable } = parked();
  assert.equal(f.start(readable, writable).outcome, "err");
  assert.equal(f.calls.spawn.length, 0);
  unlocked(readable, writable);
});

for (const options of [null, { signal: {} }, { signal: 1 }]) {
  test("invalid options leave streams caller-owned: " + JSON.stringify(options), t => {
    const f = fixture(t);
    const { readable, writable } = parked();
    assert.equal(f.start(readable, writable, options).outcome, "err");
    assert.equal(f.calls.spawn.length, 0);
    unlocked(readable, writable);
  });
}

test("untracked and closing scopes refuse before native pulls or task admission", async t => {
  const f = fixture(t);
  let pulls = 0, cancels = 0, aborts = 0;
  const { readable, writable } = parked({
    pull() { pulls++; }, cancel() { cancels++; },
  }, { abort() { aborts++; } });
  assert.equal(f.start(readable, writable, {}, "missing").outcome, "err");
  f.closing.add("owner");
  assert.equal(f.start(readable, writable).outcome, "err");
  await turn();
  assert.deepEqual([pulls, cancels, aborts, f.calls.spawn.length], [0, 0, 0, 0]);
  unlocked(readable, writable);
});

test("task admission refusal leaves streams untouched and available to their caller", async t => {
  const f = fixture(t, { refuseSpawn: true });
  let pulls = 0, cancels = 0, aborts = 0;
  const { readable, writable } = parked({
    pull(controller) { pulls++; controller.enqueue("caller"); controller.close(); },
    cancel() { cancels++; },
  }, { abort() { aborts++; } });
  assert.equal(f.start(readable, writable).outcome, "err");
  await turn();
  assert.deepEqual([pulls, cancels, aborts, f.calls.spawn.length, f.tasks.size], [0, 0, 0, 1, 0]);
  unlocked(readable, writable);
  await readable.pipeTo(writable);
  assert.equal(pulls, 1, "the original caller can still consume the refused source");
});

for (const side of ["readable", "writable"]) {
  test("a locked " + side + " is refused without touching either endpoint", async t => {
    const f = fixture(t);
    let pulls = 0;
    const { readable, writable } = parked({ pull() { pulls++; } });
    const lock = side === "readable" ? readable.getReader() : writable.getWriter();
    try {
      assert.equal(f.start(readable, writable).outcome, "err");
      await turn();
      assert.equal(pulls, 0);
      assert.equal(f.calls.spawn.length, 0);
    } finally { lock.releaseLock(); }
    unlocked(readable, writable);
  });
}

test("already-aborted signals refuse without admitting, reading, cancelling, or aborting", async t => {
  const f = fixture(t);
  let pulls = 0, cancels = 0, aborts = 0;
  const { readable, writable } = parked({
    pull() { pulls++; }, cancel() { cancels++; },
  }, { abort() { aborts++; } });
  const controller = new AbortController();
  const reason = { private: "caller-owned abort reason" };
  controller.abort(reason);
  const result = f.start(readable, writable, { signal: controller.signal });
  assert.equal(result.outcome, "cancelled");
  await turn();
  assert.deepEqual([pulls, cancels, aborts, f.calls.spawn.length], [0, 0, 0, 0]);
  assert.equal(controller.signal.reason, reason);
  unlocked(readable, writable);
});

test("native FIFO preserves arbitrary chunks and waits for sink close before task publication", async t => {
  const f = fixture(t);
  const closeEntered = deferred(), releaseClose = deferred(), received = [];
  f.releases.push(releaseClose.resolve);
  const chunks = [{ sequence: 1 }, Uint8Array.of(0, 255), "text", undefined, null];
  let index = 0;
  const { readable, writable } = parked({
    pull(controller) {
      if (index === chunks.length) controller.close();
      else controller.enqueue(chunks[index++]);
    },
  }, {
    write(chunk) { received.push(chunk); },
    close() { closeEntered.resolve(); return releaseClose.promise; },
  });
  const handle = value(f.start(readable, writable));
  await bounded(closeEntered.promise);
  await pending(handle.closed);
  assert.equal(f.tasks.size, 1);
  assert.equal(f.calls.join.length, 0);
  assert.equal(received.length, chunks.length);
  for (let i = 0; i < chunks.length; i++) assert.equal(received[i], chunks[i]);
  releaseClose.resolve();
  assert.equal((await bounded(handle.closed)).outcome, "ok");
  assert.equal((await handle.retire()).outcome, "ok");
  assert.equal(f.tasks.size, 0);
  assert.equal(f.calls.join.length, 1);
  assert.equal(f.calls.cancel.length, 0);
  unlocked(readable, writable);
});

test("backpressure keeps the next read behind an in-flight native write", async t => {
  const f = fixture(t), writing = deferred(), release = deferred();
  f.releases.push(release.resolve);
  let pulls = 0, writes = 0;
  const { readable, writable } = parked({
    pull(controller) {
      pulls++;
      if (pulls <= 2) controller.enqueue(pulls); else controller.close();
    },
  }, {
    write() {
      writes++;
      if (writes === 1) { writing.resolve(); return release.promise; }
    },
  });
  const handle = value(f.start(readable, writable));
  await bounded(writing.promise);
  await turn();
  assert.equal(pulls, 1);
  assert.equal(writes, 1);
  assert.equal(f.tasks.size, 1);
  release.resolve();
  assert.equal((await bounded(handle.closed)).outcome, "ok");
  assert.equal(writes, 2);
  unlocked(readable, writable);
});

test("scope cancellation waits for a parked write, source cancellation, and sink abort", async t => {
  const f = fixture(t);
  const writing = deferred(), releaseWrite = deferred(), aborting = deferred(), releaseAbort = deferred();
  const cancelling = deferred(), releaseCancel = deferred();
  f.releases.push(releaseWrite.resolve, releaseAbort.resolve, releaseCancel.resolve);
  const events = [];
  let pulled = false;
  const { readable, writable } = parked({
    pull(controller) { if (!pulled) { pulled = true; controller.enqueue("in-flight"); } },
    cancel() { events.push("source cancel"); cancelling.resolve(); return releaseCancel.promise; },
  }, {
    write() { events.push("write"); writing.resolve(); return releaseWrite.promise; },
    abort() { events.push("sink abort"); aborting.resolve(); return releaseAbort.promise; },
    close() { assert.fail("a cancelled pipe must not close the sink successfully"); },
  });
  const handle = value(f.start(readable, writable));
  await bounded(writing.promise);
  f.closing.add("owner");
  const closing = f.manager.drainScopes(new Set(["owner"]), "scope_close");
  await pending(closing);
  await pending(handle.closed);
  assert.equal(f.calls.join.length, 0);
  assert.equal(f.tasks.size, 1);
  releaseWrite.resolve();
  await bounded(Promise.all([aborting.promise, cancelling.promise]));
  await pending(closing);
  releaseAbort.resolve();
  await pending(closing);
  releaseCancel.resolve();
  assert.equal((await bounded(closing)).outcome, "ok");
  assert.equal((await bounded(handle.closed)).outcome, "cancelled");
  assert.equal(f.tasks.size, 0);
  assert.deepEqual(events, ["write", "sink abort", "source cancel"]);
  unlocked(readable, writable);
});

for (const refuseCancel of [false, true]) {
  test("cancelled rejected write awaits skipped source cleanup; task cancellation refused=" + refuseCancel, async t => {
    const faults = { refuseCancel }, f = fixture(t, faults);
    const writing = deferred(), write = deferred(), cancelling = deferred(), cleanup = deferred();
    f.releases.push(write.resolve, cleanup.resolve);
    let pulled = false, cancels = 0, aborts = 0;
    const { readable, writable } = parked({
      pull(controller) { if (!pulled) { pulled = true; controller.enqueue("unsent"); } },
      cancel() { cancels++; cancelling.resolve(); return cleanup.promise; },
    }, {
      write() { writing.resolve(); return write.promise; },
      abort() { aborts++; },
      close() { assert.fail("a rejected write cannot close the sink successfully"); },
    });
    Object.defineProperty(readable, "cancel", { value() { assert.fail("instance cancel invoked"); } });
    Object.defineProperty(writable, "abort", { value() { assert.fail("instance abort invoked"); } });
    const handle = value(f.start(readable, writable));
    await bounded(writing.promise);
    f.closing.add("owner");
    const closing = f.manager.drainScopes(new Set(["owner"]), "scope_close");
    write.reject(new Error("PRIVATE_REJECTED_WRITE"));
    await bounded(cancelling.promise);
    await pending(closing);
    await pending(handle.closed);
    assert.equal(f.tasks.size, 1);
    assert.equal(f.calls.join.length, 0);
    unlocked(readable, writable);
    const other = parked();
    assert.equal(f.start(readable, other.writable, {}, "sibling").outcome, "err");
    assert.equal(f.start(other.readable, writable, {}, "sibling").outcome, "err");
    assert.equal(f.calls.spawn.length, 1, "recovery retains both SDK endpoint reservations");
    cleanup.resolve();
    const receipt = await bounded(closing), terminal = await bounded(handle.closed);
    assert.equal(receipt.outcome, "err");
    assert.equal(terminal.outcome, "err");
    if (refuseCancel) {
      assert.equal(f.tasks.size, 1);
      faults.refuseCancel = false;
      assert.equal((await bounded(handle.retire("retry publication"))).outcome, "err");
    } else {
      assert.equal(terminal.failure.message, "Native stream pipe failed", "write failure stays terminal");
    }
    assert.equal(f.tasks.size, 0);
    assert.equal(f.calls.join.length, 1);
    assert.equal(cancels, 1);
    assert.equal(aborts, 0, "an errored writable cannot replay its underlying abort hook");
    assert.doesNotMatch(JSON.stringify({ receipt, terminal }), /PRIVATE_REJECTED_WRITE|PRIVATE_AUTHORITY/);
    assert.equal((await bounded(handle.retire())).outcome, "ok");
    assert.equal(cancels, 1, "retirement retry must not replay accepted source cleanup");
    unlocked(readable, writable);
  });
}

test("recovered source cleanup failure stays separate from the original write failure", async t => {
  const f = fixture(t), writing = deferred(), write = deferred(), cancelling = deferred(), cleanup = deferred();
  f.releases.push(write.resolve, cleanup.resolve);
  let pulled = false, cancels = 0;
  const { readable, writable } = parked({
    pull(controller) { if (!pulled) { pulled = true; controller.enqueue("unsent"); } },
    cancel() { cancels++; cancelling.resolve(); return cleanup.promise; },
  }, { write() { writing.resolve(); return write.promise; } });
  const handle = value(f.start(readable, writable));
  await bounded(writing.promise);
  const retiring = handle.retire("owner closing");
  write.reject(new Error("PRIVATE_REJECTED_WRITE"));
  await bounded(cancelling.promise);
  await pending(retiring);
  assert.equal(f.calls.join.length, 0);
  cleanup.reject(new Error("PRIVATE_RECOVERED_CLEANUP"));
  const receipt = await bounded(retiring), terminal = await bounded(handle.closed);
  assert.equal(receipt.outcome, "err");
  assert.equal(receipt.failure.message, "Stream pipe source cancellation failed");
  assert.equal(terminal.outcome, "err");
  assert.equal(terminal.failure.message, "Native stream pipe failed");
  assert.equal(f.tasks.size, 0);
  assert.equal(cancels, 1);
  assert.doesNotMatch(JSON.stringify({ receipt, terminal }), /PRIVATE_REJECTED_WRITE|PRIVATE_RECOVERED_CLEANUP|PRIVATE_AUTHORITY/);
  assert.equal((await bounded(handle.retire())).outcome, "ok");
  assert.equal(cancels, 1);
  unlocked(readable, writable);
});

test("recovery keeps ownership when a source cleanup callback takes a foreign native lock", async t => {
  const f = fixture(t), writing = deferred(), write = deferred();
  let pulled = false, cancels = 0, reader;
  f.releases.push(write.resolve, () => { reader?.releaseLock(); reader = undefined; });
  const { readable, writable } = parked({
    pull(controller) { if (!pulled) { pulled = true; controller.enqueue("unsent"); } },
    cancel() { cancels++; reader = readable.getReader(); },
  }, { write() { writing.resolve(); return write.promise; } });
  const handle = value(f.start(readable, writable));
  await bounded(writing.promise);
  const retiring = handle.retire("owner closing");
  write.reject(new Error("PRIVATE_REJECTED_WRITE"));
  const receipt = await bounded(retiring);
  assert.equal(receipt.outcome, "err");
  assert.equal(receipt.failure.recoverability, "transient");
  assert.equal(f.calls.join.length, 0);
  assert.equal(f.tasks.size, 1);
  assert.equal(cancels, 1);
  reader.releaseLock(); reader = undefined;
  const other = parked();
  assert.equal(f.start(readable, other.writable, {}, "sibling").outcome, "err");
  assert.equal(f.calls.spawn.length, 1);
  assert.equal((await bounded(handle.retire("retry after unlocking"))).outcome, "err");
  assert.equal(f.tasks.size, 0);
  assert.equal(f.calls.join.length, 1);
  assert.equal(cancels, 1);
  assert.equal((await bounded(handle.retire())).outcome, "ok");
  unlocked(readable, writable);
});

test("caller AbortSignal is borrowed and manual cancellation does not abort it", async t => {
  const f = fixture(t), controller = new AbortController();
  const add = controller.signal.addEventListener, remove = controller.signal.removeEventListener;
  const before = getEventListeners(controller.signal, "abort").length;
  const { readable, writable } = parked();
  const handle = value(f.start(readable, writable, { signal: controller.signal }));
  assert.equal((await bounded(handle.cancel("owned cancellation"))).outcome, "cancelled");
  assert.equal(controller.signal.aborted, false);
  assert.equal(controller.signal.addEventListener, add);
  assert.equal(controller.signal.removeEventListener, remove);
  assert.equal(getEventListeners(controller.signal, "abort").length, before);
  unlocked(readable, writable);
});

test("external abort cancels both endpoints and completes one owned task", async t => {
  const f = fixture(t), controller = new AbortController();
  const calls = [];
  const { readable, writable } = parked({ cancel() { calls.push("cancel"); } },
    { abort() { calls.push("abort"); } });
  const handle = value(f.start(readable, writable, { signal: controller.signal }));
  controller.abort({ secret: "not a public diagnostic" });
  assert.equal((await bounded(handle.closed)).outcome, "cancelled");
  assert.deepEqual(calls.sort(), ["abort", "cancel"]);
  assert.equal(f.calls.cancel.length, 1);
  assert.equal(f.calls.join.length, 1);
  assert.equal(f.tasks.size, 0);
  unlocked(readable, writable);
});

test("native write failure aborts the source and publishes failure after locks release", async t => {
  const f = fixture(t);
  const secret = new Error("PRIVATE_NATIVE_WRITE_DETAIL");
  let cancels = 0, seen = false;
  const { readable, writable } = parked({
    pull(controller) { if (!seen) { seen = true; controller.enqueue("failing"); } },
    cancel(reason) { assert.equal(reason, secret); cancels++; },
  }, { write() { throw secret; } });
  const handle = value(f.start(readable, writable));
  const closed = await bounded(handle.closed);
  assert.equal(closed.outcome, "err");
  assert.doesNotMatch(JSON.stringify(closed), /PRIVATE_NATIVE_WRITE_DETAIL|PRIVATE_AUTHORITY/);
  assert.equal(cancels, 1);
  assert.equal(f.calls.join.length, 1);
  assert.equal(f.calls.join[0].outcome.outcome, "err");
  assert.equal(f.tasks.size, 0);
  unlocked(readable, writable);
});

for (const endpoint of ["source", "sink"]) {
  test("native " + endpoint + " cleanup rejection cannot become successful retirement", async t => {
    const f = fixture(t);
    const { readable, writable } = parked({
      cancel() { if (endpoint === "source") throw new Error("PRIVATE_SOURCE_CLEANUP"); },
    }, {
      abort() { if (endpoint === "sink") throw new Error("PRIVATE_SINK_CLEANUP"); },
    });
    const handle = value(f.start(readable, writable));
    const retired = await bounded(handle.retire("owner closing"));
    assert.equal(retired.outcome, "err");
    const closed = await bounded(handle.closed);
    assert.equal(closed.outcome, "err");
    assert.doesNotMatch(JSON.stringify({ retired, closed }), /PRIVATE_SOURCE_CLEANUP|PRIVATE_SINK_CLEANUP|PRIVATE_AUTHORITY/);
    unlocked(readable, writable);
  });
}

for (const fault of ["refuseCancel", "throwCancel", "refuseJoin", "throwJoin", "inconsistentJoin"]) {
  test("a " + fault + " receipt retains ownership until explicit successful retry", async t => {
    const faults = { [fault]: true }, f = fixture(t, faults);
    let cancels = 0, aborts = 0;
    const { readable, writable } = parked({ cancel() { cancels++; } }, { abort() { aborts++; } });
    const handle = value(f.start(readable, writable));
    assert.equal((await bounded(handle.retire("retire once"))).outcome, "err");
    assert.equal(f.tasks.size, 1);
    assert.equal((await bounded(handle.closed)).outcome, "err");
    unlocked(readable, writable);
    faults[fault] = false;
    assert.equal((await bounded(handle.retire("retry owned cleanup"))).outcome, "ok");
    assert.equal(f.tasks.size, 0);
    assert.deepEqual([cancels, aborts], [1, 1], "retry does not replay native terminal effects");
    assert.equal((await handle.closed).outcome, "err", "first terminal observation remains immutable");
  });
}

test("natural EOF publication refusal retains the task without restarting native work", async t => {
  const faults = { refuseJoin: true }, f = fixture(t, faults);
  let closes = 0, pulls = 0;
  const { readable, writable } = parked({
    pull(controller) { pulls++; controller.close(); },
  }, { close() { closes++; } });
  const handle = value(f.start(readable, writable));
  assert.equal((await bounded(handle.closed)).outcome, "err");
  assert.equal(f.tasks.size, 1);
  assert.equal(f.calls.cancel.length, 0);
  faults.refuseJoin = false;
  assert.equal((await bounded(handle.retire())).outcome, "ok");
  assert.deepEqual([pulls, closes, f.tasks.size], [1, 1, 0]);
  assert.equal(f.calls.cancel.length, 0, "finished successful work is not retroactively cancelled");
});

test("native stream intrinsics ignore overridable instance methods and locked properties", async t => {
  const f = fixture(t);
  const seen = [];
  const { readable, writable } = parked({
    pull(controller) { controller.enqueue("native"); controller.close(); },
  }, { write(chunk) { seen.push(chunk); } });
  for (const method of ["pipeTo", "getReader", "cancel"]) {
    Object.defineProperty(readable, method, { value() { assert.fail("overridden readable method invoked"); } });
  }
  for (const method of ["getWriter", "abort", "close"]) {
    Object.defineProperty(writable, method, { value() { assert.fail("overridden writable method invoked"); } });
  }
  Object.defineProperty(readable, "locked", { get() { assert.fail("instance readable locked getter invoked"); } });
  Object.defineProperty(writable, "locked", { get() { assert.fail("instance writable locked getter invoked"); } });
  const handle = value(f.start(readable, writable));
  assert.equal((await bounded(handle.closed)).outcome, "ok");
  assert.deepEqual(seen, ["native"]);
  unlocked(readable, writable);
});

test("reentrant option getters cannot admit work after their owner closes", async t => {
  const f = fixture(t);
  let pulls = 0;
  const { readable, writable } = parked({ pull() { pulls++; } });
  const options = { get signal() { f.closing.add("owner"); return null; } };
  assert.equal(f.start(readable, writable, options).outcome, "err");
  await turn();
  assert.equal(f.calls.spawn.length, 0);
  assert.equal(pulls, 0);
  unlocked(readable, writable);
});

test("reentrant owner closure during admission cancels without pulling or writing", async t => {
  const faults = {}, f = fixture(t, faults);
  let pulls = 0, writes = 0, cancels = 0, aborts = 0;
  const { readable, writable } = parked({
    pull(controller) { pulls++; controller.enqueue("must not escape"); },
    cancel() { cancels++; },
  }, { write() { writes++; }, abort() { aborts++; } });
  faults.onSpawn = () => { f.closing.add("owner"); };
  const handle = value(f.start(readable, writable));
  assert.equal((await bounded(handle.closed)).outcome, "cancelled");
  assert.deepEqual([pulls, writes, cancels, aborts, f.tasks.size], [0, 0, 1, 1, 0]);
  assert.equal(f.calls.cancel.length, 1);
  assert.equal(f.calls.join.length, 1);
  unlocked(readable, writable);
});

test("signal abort during admission cancels without pulling or writing", async t => {
  const faults = {}, f = fixture(t, faults), controller = new AbortController();
  let pulls = 0, writes = 0;
  const { readable, writable } = parked({
    pull(source) { pulls++; source.enqueue("must not escape"); },
  }, { write() { writes++; } });
  faults.onSpawn = () => controller.abort("admission cancelled");
  const handle = value(f.start(readable, writable, { signal: controller.signal }));
  assert.equal((await bounded(handle.closed)).outcome, "cancelled");
  assert.deepEqual([pulls, writes, f.tasks.size], [0, 0, 0]);
  assert.equal(f.calls.cancel.length, 1);
  assert.equal(f.calls.join.length, 1);
  unlocked(readable, writable);
});

test("streams are reserved before reentrant task admission tries to adopt them again", async t => {
  const faults = {}, f = fixture(t, faults);
  const { readable, writable } = parked();
  let nested;
  faults.onSpawn = () => { nested = f.start(readable, writable, {}, "sibling"); };
  const handle = value(f.start(readable, writable));
  assert.equal(nested.outcome, "err");
  assert.equal(f.calls.spawn.length, 1);
  assert.equal((await bounded(handle.cancel())).outcome, "cancelled");
  assert.equal(f.tasks.size, 0);
  unlocked(readable, writable);
});

test("publication refusal retains endpoint ownership even after native locks release", async t => {
  const faults = { refuseJoin: true }, f = fixture(t, faults);
  const first = parked({ pull(controller) { controller.close(); } });
  const handle = value(f.start(first.readable, first.writable));
  assert.equal((await bounded(handle.closed)).outcome, "err");
  unlocked(first.readable, first.writable);
  const second = parked(), third = parked();
  assert.equal(f.start(first.readable, second.writable, {}, "sibling").outcome, "err");
  assert.equal(f.start(third.readable, first.writable, {}, "sibling").outcome, "err");
  assert.equal(f.calls.spawn.length, 1, "native unlocking is not ABI ownership release");
  assert.equal(f.tasks.size, 1);
  faults.refuseJoin = false;
  assert.equal((await bounded(handle.retire())).outcome, "ok");
  assert.equal(f.tasks.size, 0);
  unlocked(second.readable, second.writable);
  unlocked(third.readable, third.writable);
});

test("reentrant cancellation and publication share retirement without double joining", async t => {
  const faults = {}, f = fixture(t, faults), reentrant = [];
  const { readable, writable } = parked();
  const handle = value(f.start(readable, writable));
  faults.onCancel = () => reentrant.push(handle.retire("from cancel adapter"));
  faults.onJoin = () => reentrant.push(handle.retire("from join adapter"));
  assert.equal((await bounded(handle.retire("outer retirement"))).outcome, "ok");
  for (const receipt of await bounded(Promise.all(reentrant))) assert.equal(receipt.outcome, "ok");
  assert.equal(f.calls.cancel.length, 1);
  assert.equal(f.calls.join.length, 1);
  assert.equal(f.tasks.size, 0);
});

test("scope drain isolates siblings and task cancellation already admitted is not duplicated", async t => {
  const f = fixture(t);
  const first = parked(), second = parked();
  const a = value(f.start(first.readable, first.writable));
  const b = value(f.start(second.readable, second.writable, {}, "sibling"));
  f.closing.add("owner");
  assert.equal((await bounded(f.manager.drainScopes(new Set(["owner"]), "scope_close"))).outcome, "ok");
  assert.equal((await bounded(a.closed)).outcome, "cancelled");
  await pending(b.closed);
  assert.equal(f.tasks.size, 1);
  f.manager.cancelTask("task:2:PRIVATE_AUTHORITY", "caller_cancel", "already admitted");
  assert.equal((await bounded(b.closed)).outcome, "cancelled");
  assert.equal(f.calls.cancel.length, 1, "only the first task needs manager admission");
  assert.equal(f.tasks.size, 0);
  unlocked(first.readable, first.writable);
  unlocked(second.readable, second.writable);
});
