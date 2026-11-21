/**
 * Reliable WebTransport cleanup receipts with native WHATWG streams.
 * Run: node --unhandled-rejections=strict --test scripts/test_browser_webtransport_cleanup.mjs
 * This executes the shared manager, including native locking and backpressure.
 * Session creation and selected lock-release faults are controlled fixtures;
 * no Rust, WASM, browser-engine, or live HTTP/3 execution is claimed.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const sourcePath = process.env.ASUPERSYNC_WEBTRANSPORT_STREAM_SOURCE
  ?? new URL("../packages/browser-core/webtransport-streams.js", import.meta.url);
const source = await readFile(sourcePath, "utf8");
const { createReliableStreamManager, WEBTRANSPORT_STREAM_LIMITS } = await import(
  `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`,
);
console.log(JSON.stringify({
  scenario_id: "browser-webtransport-cleanup-receipts",
  source_sha256: createHash("sha256").update(source).digest("hex"),
  evidence_scope: "shared reliable-stream manager, native WHATWG streams, controlled release faults",
}));

const ok = (value) => ({ outcome: "ok", value });
const fail = (code, recoverability, message) => ({ outcome: "err", failure: { code, recoverability, message } });
const cancelled = (message, origin) => ({ outcome: "cancelled", cancellation: { message, origin } });
const turn = () => new Promise((resolve) => setImmediate(resolve));

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function fixture(transport = {}) {
  const state = { closed: false, sessionOrigin: "cleanup-tests", transport: {
    ready: Promise.resolve(), ...transport,
  } };
  const manager = createReliableStreamManager({ lookup: () => state, ok, fail, cancelled });
  const terminal = cancelled("owner closed", state.sessionOrigin);
  return { manager, state, terminal, stop: () => manager.closeSession(state, terminal) };
}

function unwrap(outcome) {
  assert.equal(outcome.outcome, "ok", JSON.stringify(outcome));
  return outcome.value;
}

function assertFailure(outcome, pattern) {
  assert.equal(outcome.outcome, "err");
  assert.equal(outcome.failure.code, "internal_failure");
  assert.equal(outcome.failure.recoverability, "transient");
  assert.match(outcome.failure.message, pattern);
}

function wire(options = {}) {
  const events = [];
  let input;
  const readable = new ReadableStream({
    start(controller) { input = controller; },
    cancel(reason) { events.push("cancel"); return options.cancel?.(reason); },
  }, { highWaterMark: 0 });
  const writable = new WritableStream({
    write(value) { events.push("write"); return options.write?.(value); },
    close() { events.push("finish"); },
    abort(reason) { events.push("abort"); return options.abort?.(reason); },
  });
  return { readable, writable, input, events };
}

function faultRelease(endpoint, method, fault) {
  const acquire = endpoint[method].bind(endpoint);
  endpoint[method] = () => {
    const lock = acquire();
    const release = lock.releaseLock.bind(lock);
    lock.releaseLock = () => { fault(); release(); };
    return lock;
  };
}

test("cleanup receipt waits for closure and preserves the first owner outcome", { timeout: 3000 }, async () => {
  const f = fixture();
  const first = f.manager.drainCleanup(f.state);
  assert.equal(f.manager.drainCleanup(f.state), first);
  let settled = false;
  void first.then(() => { settled = true; });
  await turn();
  assert.equal(settled, false);
  const primary = fail("internal_failure", "permanent", "operation failed before cleanup");
  f.manager.closeSession(f.state, primary);
  f.stop();
  assert.equal(await f.manager.whenClosed(f.state), primary);
  unwrap(await first);
  unwrap(await f.manager.drainCleanup(f.state));
});

test("cleanup waits for native writes, cancellation, and abort before reporting success", { timeout: 3000 }, async () => {
  const write = deferred();
  const cancel = deferred();
  const abort = deferred();
  const host = wire({ write: () => write.promise, cancel: () => cancel.promise, abort: () => abort.promise });
  const f = fixture({ createBidirectionalStream: async () => host });
  const stream = unwrap(await f.manager.open({ session: "session" }));
  const writing = stream.write(Uint8Array.of(1));
  await turn();
  f.stop();
  const receipt = f.manager.drainCleanup(f.state);
  assert.equal(f.manager.drainCleanup(f.state), receipt);
  let settled = false;
  void receipt.then(() => { settled = true; });
  try {
    await turn();
    assert.equal(settled, false);
    assert.equal(host.writable.locked, true);
    assert.equal(host.events.includes("abort"), false, "native abort waits for the admitted write");
    write.resolve();
    cancel.resolve();
    await turn();
    assert.equal(host.events.includes("abort"), true);
    assert.equal(settled, false, "the sink still owns asynchronous abort cleanup");
    abort.resolve();
    unwrap(await receipt);
    assert.equal(await writing, f.terminal);
    assert.equal(await stream.closed, f.terminal);
    assert.equal(await f.manager.whenClosed(f.state), f.terminal);
    assert.equal(host.readable.locked, false);
    assert.equal(host.writable.locked, false);
  } finally { write.resolve(); cancel.resolve(); abort.resolve(); }
});

test("rejected native cancel and abort stay visible once after both locks release", { timeout: 3000 }, async () => {
  const host = wire({
    cancel: () => Promise.reject(new Error("source cleanup refused")),
    abort: () => Promise.reject(new Error("sink cleanup refused")),
  });
  const f = fixture({ createBidirectionalStream: async () => host });
  const stream = unwrap(await f.manager.open({ session: "session" }));
  f.stop();
  assertFailure(await f.manager.drainCleanup(f.state), /cleanup refused/);
  assert.equal(await stream.closed, f.terminal);
  assert.equal(host.readable.locked, false);
  assert.equal(host.writable.locked, false);
  unwrap(await f.manager.drainCleanup(f.state));
  assert.deepEqual(host.events, ["cancel", "abort"], "retry never repeats settled host shutdown");
});

test("failed releases require explicit retry and coalesce reentrant cleanup calls", { timeout: 3000 }, async () => {
  const host = wire();
  let refuse = true;
  let releaseCalls = 0;
  const reentered = [];
  let f;
  for (const [endpoint, method] of [[host.readable, "getReader"], [host.writable, "getWriter"]]) {
    faultRelease(endpoint, method, () => {
      releaseCalls += 1;
      if (releaseCalls > 2) reentered.push(f.manager.drainCleanup(f.state));
      if (refuse) throw new Error("release still refused");
    });
  }
  f = fixture({ createBidirectionalStream: async () => host });
  const stream = unwrap(await f.manager.open({ session: "session" }));
  try {
    f.stop();
    const first = f.manager.drainCleanup(f.state);
    assertFailure(await first, /release still refused/);
    assert.equal(await stream.closed, f.terminal);
    assert.equal(releaseCalls, 2, "completion cannot silently retry discard's failed releases");
    assert.equal(host.readable.locked, true);
    assert.equal(host.writable.locked, true);
    const second = f.manager.drainCleanup(f.state);
    assertFailure(await second, /release still refused/);
    assert.equal(releaseCalls, 4);
    assert.ok(reentered.every((promise) => promise === second));
    reentered.length = 0;
    refuse = false;
    const third = f.manager.drainCleanup(f.state);
    unwrap(await third);
    assert.equal(releaseCalls, 6);
    assert.ok(reentered.every((promise) => promise === third));
    assert.equal(host.readable.locked, false);
    assert.equal(host.writable.locked, false);
    assert.deepEqual(host.events, ["cancel", "abort"]);
  } finally { refuse = false; await f.manager.drainCleanup(f.state); }
});

test("late-created stream cleanup contributes its failure without changing admission terminal", { timeout: 3000 }, async () => {
  const creation = deferred();
  const cancellation = deferred();
  const host = wire({ cancel: () => cancellation.promise });
  const f = fixture({ createBidirectionalStream: () => creation.promise });
  const opening = f.manager.open({ session: "session" });
  await turn();
  f.stop();
  const receipt = f.manager.drainCleanup(f.state);
  let settled = false;
  void receipt.then(() => { settled = true; });
  try {
    creation.resolve(host);
    await turn();
    assert.equal(settled, false, "late endpoint disposal remains owned");
    cancellation.reject(new Error("late source cleanup refused"));
    assertFailure(await receipt, /late source cleanup refused/);
    assert.equal(await opening, f.terminal);
    assert.equal(await f.manager.whenClosed(f.state), f.terminal);
    unwrap(await f.manager.drainCleanup(f.state));
    assert.deepEqual(host.events, ["cancel", "abort"]);
    assert.equal(host.readable.locked, false);
    assert.equal(host.writable.locked, false);
  } finally { creation.resolve(host); cancellation.resolve(); }
});

test("incoming collection cancellation and release failures remain retryable", { timeout: 3000 }, async () => {
  let cancellationCalls = 0;
  let releaseCalls = 0;
  const collection = new ReadableStream({
    cancel() { cancellationCalls += 1; return Promise.reject(new Error("incoming cleanup refused")); },
  }, { highWaterMark: 0 });
  faultRelease(collection, "getReader", () => {
    releaseCalls += 1;
    if (releaseCalls === 1) throw new Error("incoming release refused");
  });
  const f = fixture({ incomingUnidirectionalStreams: collection });
  const accepting = f.manager.accept({ session: "session" }, "unidirectional");
  await turn();
  assert.equal(collection.locked, true);
  f.stop();
  assertFailure(await f.manager.drainCleanup(f.state), /incoming cleanup refused/);
  assert.equal(await accepting, f.terminal);
  assert.equal(collection.locked, true);
  assert.equal(releaseCalls, 1);
  unwrap(await f.manager.drainCleanup(f.state));
  assert.equal(collection.locked, false);
  assert.equal(releaseCalls, 2);
  assert.equal(cancellationCalls, 1);
});

test("normal EOF and FIN retain failed locks even after stream.closed succeeds", { timeout: 3000 }, async () => {
  const host = wire();
  let refuse = true;
  for (const [endpoint, method] of [[host.readable, "getReader"], [host.writable, "getWriter"]]) {
    faultRelease(endpoint, method, () => { if (refuse) throw new Error("completed endpoint release refused"); });
  }
  const f = fixture({ createBidirectionalStream: async () => host });
  const stream = unwrap(await f.manager.open({ session: "session" }));
  try {
    host.input.close();
    assert.deepEqual(unwrap(await stream.read()), { done: true });
    unwrap(await stream.finish());
    unwrap(await stream.closed);
    f.stop();
    assertFailure(await f.manager.drainCleanup(f.state), /completed endpoint release refused/);
    assert.equal(host.readable.locked, true);
    assert.equal(host.writable.locked, true);
    refuse = false;
    unwrap(await f.manager.drainCleanup(f.state));
    assert.equal(host.readable.locked, false);
    assert.equal(host.writable.locked, false);
    assert.deepEqual(host.events, ["finish"], "completed halves are not cancelled again");
  } finally { refuse = false; f.stop(); await f.manager.drainCleanup(f.state); }
});

test("failed attachment releases stay bounded by stream capacity and recover on explicit retry", { timeout: 5000 }, async () => {
  let refuse = true;
  const hosts = [];
  const f = fixture({ createBidirectionalStream: async () => {
    const host = wire();
    faultRelease(host.readable, "getReader", () => { if (refuse) throw new Error("partial attachment release refused"); });
    host.writable.getWriter = () => null;
    hosts.push(host);
    return host;
  } });
  try {
    for (let i = 0; i < WEBTRANSPORT_STREAM_LIMITS.maxStreamsPerSession; i += 1) {
      assertFailure(await f.manager.open({ session: "session" }), /invalid stream lock/);
    }
    const exhausted = await f.manager.open({ session: "session" });
    assert.equal(exhausted.outcome, "err");
    assert.equal(exhausted.failure.code, "compatibility_rejected");
    assert.match(exhausted.failure.message, /capacity exhausted/);
    assert.equal(hosts.length, WEBTRANSPORT_STREAM_LIMITS.maxStreamsPerSession);
    assert.ok(hosts.every((host) => host.readable.locked));
    f.stop();
    assertFailure(await f.manager.drainCleanup(f.state), /partial attachment release refused/);
    refuse = false;
    unwrap(await f.manager.drainCleanup(f.state));
    assert.ok(hosts.every((host) => !host.readable.locked && !host.writable.locked));
    assert.ok(hosts.every((host) => host.events.join(",") === "cancel,abort"));
  } finally { refuse = false; f.stop(); await f.manager.drainCleanup(f.state); }
});

test("explicit release retry cannot erase the passive historical retirement failure", { timeout: 3000 }, async () => {
  const host = wire();
  let releases = 0;
  faultRelease(host.writable, "getWriter", () => {
    releases += 1;
    if (releases === 1) throw new Error("initial release refused");
  });
  const f = fixture({ createBidirectionalStream: async () => host });
  unwrap(await f.manager.open({ session: "session" }));
  const retired = f.manager.whenRetired(f.state);
  f.stop();
  assertFailure(await f.manager.drainCleanup(f.state), /initial release refused/);
  const historical = await retired;
  assert.equal(historical.outcome, "err");
  assert.equal(historical.failure.recoverability, "permanent");
  assert.equal(Object.isFrozen(historical), true);
  assert.equal(Object.isFrozen(historical.failure), true);
  assert.equal(host.writable.locked, true);
  unwrap(await f.manager.drainCleanup(f.state));
  assert.equal(host.writable.locked, false);
  assert.equal(releases, 2);
  assert.equal(f.manager.whenRetired(f.state), retired);
  assert.equal(await retired, historical);
  assert.equal(historical.outcome, "err");
});

test("a hidden lock from throwing acquisition cannot become successful cleanup on retry", { timeout: 3000 }, async () => {
  const collection = new ReadableStream({}, { highWaterMark: 0 });
  const acquire = collection.getReader.bind(collection);
  let hidden;
  collection.getReader = () => { hidden = acquire(); throw new Error("acquired but not returned"); };
  const f = fixture({ incomingUnidirectionalStreams: collection });
  try {
    assertFailure(await f.manager.accept({ session: "session" }, "unidirectional"), /acquired but not returned/);
    f.stop();
    assertFailure(await f.manager.drainCleanup(f.state), /acquired but not returned/);
    assert.equal(collection.locked, true);
    const retry = await f.manager.drainCleanup(f.state);
    assert.equal(retry.outcome, "err");
    assert.equal(retry.failure.recoverability, "permanent");
    assert.match(retry.failure.message, /retirement is unconfirmed/);
    assert.equal((await f.manager.whenRetired(f.state)).outcome, "err");
  } finally { hidden?.releaseLock(); }
});
