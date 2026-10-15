/** Actual request mapper with native Streams; producer receipts are explicit doubles.
 * Run: node --experimental-vm-modules --test scripts/test_browser_fetch_request_map.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { createContext, SourceTextModule } from "node:vm";
const source = readFileSync(process.env.ASUPERSYNC_REQUEST_MAP_SOURCE ?? new URL("../packages/browser/src/fetch-request-map.ts", import.meta.url), "utf8");
console.log(JSON.stringify({ scenario: "owned-request-mapping", sha256: createHash("sha256").update(source).digest("hex"),
  scope: "actual mapper; native Streams and loopback HTTP; explicit producer receipts" }));
async function load(globals = {}) {
  const module = new SourceTextModule(stripTypeScriptTypes(source, { mode: "transform" }), {
    context: createContext({ ReadableStream, ReadableStreamDefaultReader, AbortController, ...globals }),
  });
  await module.link(() => assert.fail("mapper added a runtime dependency"));
  await module.evaluate(); return module.namespace;
}
const api = await load();
const ok = value => ({ outcome: "ok", value });
const err = (message = "application") => ({ outcome: "err", failure: { code: "decode_failure", recoverability: "permanent", message } });
const cancelled = (message = "producer cancelled") => ({ outcome: "cancelled", cancellation: { kind: "test", phase: "completed",
  origin_region: "producer", origin_task: null, timestamp_nanos: 0, message, truncated: false } });
const panic = (message = "producer panic") => ({ outcome: "panicked", message });
const message = outcome => outcome.outcome === "err" ? outcome.failure.message : outcome.outcome === "cancelled" ? outcome.cancellation.message : outcome.message;
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
async function pending(promise) { let done = false; void promise.then(() => { done = true; }, () => { done = true; }); await turn(); assert.equal(done, false); }
function fixture(t, options = {}) {
  const calls = { pulls: 0, native: 0, owner: 0, mapped: [] }, gates = [], handles = [], readers = [];
  const terminal = deferred(); let controller, pos = 0;
  const gate = () => { const value = deferred(); gates.push(value); return value; };
  const readable = new ReadableStream({
    start(c) { controller = c; },
    pull(c) {
      calls.pulls++;
      if (options.parkInput) return;
      if (pos < (options.count ?? 3)) c.enqueue(pos++);
      else { c.close(); if (!options.holdTerminal) terminal.resolve(options.terminal ?? ok(undefined)); }
    },
    async cancel() {
      calls.native++; await options.nativeGate?.promise;
      if (!options.owned && !options.holdTerminal) terminal.resolve(cancelled());
      if (options.nativeRefuses) throw new Error("native refused");
    },
  }, { highWaterMark: 0 });
  const owner = { readable, closed: terminal.promise, async cancel() {
    assert.equal(this, owner); calls.owner++; await options.ownerGate?.promise;
    if (!options.holdTerminal) terminal.resolve(options.terminal ?? cancelled());
    return options.ownerReceipt ?? ok(undefined);
  } };
  const start = (mapper = value => ({ url: `https://example.test/${value}` }), config, typed = false, raw = !options.owned) => {
    const result = (typed ? api.tryMapFetchRequests : api.mapFetchRequests)(raw ? readable : owner,
      (...args) => { calls.mapped.push(args[1]); return mapper(...args); }, config);
    assert.equal(result.outcome, "ok"); handles.push(result.value); return result.value;
  };
  const reader = handle => { const r = handle.readable.getReader(); readers.push(r); return r; };
  t.after(async () => {
    for (const g of gates) g.resolve(); options.nativeGate?.resolve(); options.ownerGate?.resolve(); terminal.resolve(ok(undefined));
    await Promise.all(handles.map(h => h.cancel("fixture cleanup")));
    for (const r of readers) { try { r.releaseLock(); } catch {} }
  });
  return { calls, readable, owner, terminal, controller, gate, start, reader };
}
for (const typed of [false, true]) {
  test(`maps in order on demand with no prefetch (${typed})`, async t => {
    const f = fixture(t), h = f.start(v => typed ? ok({ url: `${v}` }) : { url: `${v}` }, {}, typed), r = f.reader(h);
    await turn(); assert.equal(f.calls.pulls, 0);
    for (let i = 0; i < 3; i++) {
      const next = await r.read(); assert.equal(next.value.url, `${i}`); await turn();
      assert.equal(f.calls.pulls, i + 1); assert.deepEqual(f.calls.mapped, Array.from({ length: i + 1 }, (_, j) => j));
    }
    assert.equal((await r.read()).done, true); assert.equal((await h.closed).outcome, "ok"); assert.equal(f.readable.locked, false);
  });
  test(`skipped records consume input budget and preserve physical indices (${typed})`, async t => {
    const f = fixture(t, { count: 7 }); const h = f.start((v, index) => {
      assert.equal(v, index); const value = v % 2 ? null : { url: `${index}` }; return typed ? ok(value) : value;
    }, { maxInputs: 7 }, typed);
    const values = []; for await (const value of h.readable) values.push(value.url);
    assert.deepEqual(values, ["0", "2", "4", "6"]); assert.equal((await h.closed).outcome, "ok");
  });
}
test("cancellation joins an in-flight mapper after native input cancellation", async t => {
  const f = fixture(t), started = f.gate(), release = f.gate(); let signal;
  const h = f.start(async (_v, _i, s) => { signal = s; started.resolve(); await release.promise; return { url: "never emitted" }; });
  const r = f.reader(h), read = r.read(); void read.catch(() => {}); await started.promise;
  const done = h.cancel("stop mapper"); assert.equal(done, h.cancel("later")); assert.equal(signal.aborted, true);
  await pending(done); assert.equal(f.calls.native, 1); assert.equal(f.readable.locked, true);
  release.resolve(); assert.equal((await done).outcome, "cancelled"); await assert.rejects(read);
  assert.equal(f.readable.locked, false); assert.deepEqual(f.calls.mapped, [0]);
});
test("synchronous mapper cancellation installs its join before callback reentry", async t => {
  const f = fixture(t), release = f.gate(); let h;
  h = f.start(() => { void h.cancel(); return release.promise; });
  const r = f.reader(h), read = r.read(); void read.catch(() => {}); await turn(); await pending(h.closed);
  release.resolve({ url: "late" }); assert.equal((await h.closed).outcome, "cancelled"); await assert.rejects(read);
});
test("native cancellation, owner cancellation and source terminal are independent joined barriers", async t => {
  const nativeGate = deferred(), ownerGate = deferred(); const f = fixture(t, { owned: true, parkInput: true, holdTerminal: true, nativeGate, ownerGate });
  const h = f.start(), r = f.reader(h), read = r.read(); void read.catch(() => {});
  await turn(); const done = h.cancel(); await pending(done);
  assert.equal(f.calls.native, 1); assert.equal(f.calls.owner, 1);
  f.terminal.resolve(cancelled()); await pending(done); nativeGate.resolve(); await pending(done); ownerGate.resolve();
  assert.equal((await done).outcome, "cancelled"); await assert.rejects(read);
});
test("native EOF still joins producer completion", async t => {
  const f = fixture(t, { owned: true, count: 0, holdTerminal: true }); const h = f.start(), r = f.reader(h), read = r.read();
  await pending(read); await pending(h.closed); assert.equal(f.calls.owner, 0); f.terminal.resolve(ok(undefined));
  assert.equal((await read).done, true); assert.equal((await h.closed).outcome, "ok");
});
test("successful producer completion does not discard queued unread input", async t => {
  const f = fixture(t, { owned: true }); f.terminal.resolve(ok(undefined)); const h = f.start();
  await turn(); assert.equal(f.calls.pulls, 0); const values = []; for await (const v of h.readable) values.push(v.url);
  assert.equal(values.length, 3); assert.equal((await h.closed).outcome, "ok");
});
for (const outcome of [err, cancelled, panic]) {
  test(`idle producer ${outcome.name} retires the mapping stage without output demand`, async t => {
    const f = fixture(t, { owned: true, holdTerminal: true }); const h = f.start(); f.terminal.resolve(outcome("source cause"));
    const result = await h.closed; assert.equal(result.outcome, outcome().outcome); assert.equal(message(result), "source cause");
    assert.equal(f.calls.pulls, 0); assert.equal(f.calls.owner, 1); assert.equal(f.calls.native, 1);
  });
}
for (const outcome of [err, cancelled, panic]) {
  test(`late typed mapper ${outcome.name} participates in cancellation severity`, async t => {
    const f = fixture(t), started = f.gate(), release = f.gate(); const h = f.start(async () => {
      started.resolve(); await release.promise; return outcome("late cause");
    }, {}, true); const r = f.reader(h), read = r.read(); void read.catch(() => {}); await started.promise;
    void h.cancel("first cause"); await pending(h.closed); release.resolve();
    const result = await h.closed; assert.equal(result.outcome, outcome === panic ? "panicked" : "cancelled");
    assert.equal(message(result), outcome === panic ? "late cause" : "first cause"); await assert.rejects(read);
  });
}
test("mapper throwing its own cancellation signal retains cancellation", async t => {
  const f = fixture(t), started = f.gate(); const h = f.start(async (_v, _i, signal) => {
    started.resolve(); await new Promise(resolve => signal.addEventListener("abort", resolve, { once: true })); signal.throwIfAborted();
  }); const r = f.reader(h), read = r.read(); void read.catch(() => {}); await started.promise; void h.cancel();
  assert.equal((await h.closed).outcome, "cancelled"); await assert.rejects(read);
});
test("arbitrary mapper exceptions cannot forge a typed outcome via cause getters", async t => {
  const f = fixture(t); let touched = 0; const h = f.start(() => { throw { get cause() { touched++; return cancelled(); }, toString() { touched++; return "secret"; } }; });
  const r = f.reader(h); await assert.rejects(r.read()); const result = await h.closed;
  assert.equal(result.outcome, "panicked"); assert.equal(result.message, "fetch request mapper threw or rejected"); assert.equal(touched, 0);
});
for (const origin of [err, cancelled, panic]) for (const terminal of [err, panic]) {
  test(`${origin.name} mapper and ${terminal.name} producer choose stronger outcome`, async t => {
    const f = fixture(t, { owned: true, terminal: terminal("cleanup") }); const h = f.start(() => origin("mapper"), {}, true), r = f.reader(h);
    await assert.rejects(r.read()); const result = await h.closed;
    const expected = origin === panic || origin === cancelled && terminal === err ? origin : terminal;
    assert.equal(result.outcome, expected().outcome);
  });
}
for (const malformed of [undefined, null, {}, { outcome: "err", failure: {} }, { outcome: "panicked", message: 7 }]) {
  test(`typed malformed envelope ${JSON.stringify(malformed)} fails closed`, async t => {
    const f = fixture(t), h = f.start(() => malformed, {}, true), r = f.reader(h); await assert.rejects(r.read());
    assert.equal((await h.closed).failure.code, "internal_failure");
  });
}
test("typed envelope tag and panic message are snapshotted exactly once", async t => {
  const f = fixture(t); let tags = 0, messages = 0;
  const h = f.start(() => ({ get outcome() { tags++; return tags === 1 ? "panicked" : "ok"; }, get message() { messages++; return "once"; } }), {}, true);
  const r = f.reader(h); await assert.rejects(r.read()); assert.equal((await h.closed).message, "once"); assert.equal(tags, 1); assert.equal(messages, 1);
});
test("source methods/receipt are captured before ownership and preserve receiver", async t => {
  const f = fixture(t, { owned: true }); const h = f.start(); f.owner.cancel = () => assert.fail("changed method"); f.owner.closed = Promise.resolve(panic("replacement"));
  assert.equal((await h.cancel()).outcome, "cancelled"); assert.equal(f.calls.owner, 1);
});
test("raw native stream never probes arbitrary owner-shaped properties", async t => {
  const f = fixture(t); for (const key of ["readable", "closed", "cancel"]) Object.defineProperty(f.readable, key, { get() { assert.fail(key); } });
  const h = f.start(); assert.equal((await h.cancel()).outcome, "cancelled"); assert.equal(f.calls.native, 1);
});
test("invalid/locked input and invalid mapper leave source ownership untouched", async t => {
  const f = fixture(t); const held = f.readable.getReader();
  assert.equal(api.mapFetchRequests(f.readable, x => x).outcome, "err"); held.releaseLock();
  for (const mapper of [null, 1, {}]) assert.equal(api.mapFetchRequests(f.readable, mapper).outcome, "err");
  for (const maxInputs of [0, -1, 1.5, Infinity, NaN, Number.MAX_SAFE_INTEGER + 1, "5"])
    assert.equal(api.mapFetchRequests(f.readable, x => x, { maxInputs }).outcome, "err");
  assert.equal(f.readable.locked, false); assert.equal(f.calls.pulls, 0); assert.equal(f.calls.native, 0);
});
test("missing host support refuses before locking or effects", async t => {
  const restricted = await load({ AbortController: undefined }), f = fixture(t);
  assert.equal(restricted.mapFetchRequests(f.readable, x => x).outcome, "err"); assert.equal(f.readable.locked, false);
});
test("finite input cap counts skips and never calls mapper for excess input", async t => {
  const f = fixture(t, { count: 5 }), h = f.start(() => null, { maxInputs: 2 }), r = f.reader(h);
  await assert.rejects(r.read()); assert.match((await h.closed).failure.message, /maxInputs/); assert.deepEqual(f.calls.mapped, [0, 1]);
});
test("descriptor identity and body getters are untouched until downstream admission", async t => {
  const f = fixture(t, { count: 1 }); const request = { url: "https://example.test/", get body() { assert.fail("unadmitted body accessed"); } };
  const h = f.start(() => request), r = f.reader(h); assert.equal((await r.read()).value, request);
  assert.equal((await r.read()).done, true);
});
test("iterator exit joins the source owner and pipeTo failure retires it", async t => {
  for (const pipe of [false, true]) {
    const f = fixture(t, { owned: true }), h = f.start();
    if (pipe) await assert.rejects(h.readable.pipeTo(new WritableStream({ write() { throw new Error("sink failed"); } })));
    else for await (const _ of h.readable) break;
    assert.equal((await h.closed).outcome, "cancelled"); assert.equal(f.calls.owner, 1); assert.equal(f.calls.mapped.length, 1);
  }
});
test("native source errors resolve to authoritative producer cancellation", async t => {
  const f = fixture(t, { owned: true, holdTerminal: true }), h = f.start();
  f.controller.error(new Error("transport")); await pending(h.closed); f.terminal.resolve(cancelled("upstream stop"));
  const result = await h.closed; assert.equal(result.outcome, "cancelled"); assert.equal(message(result), "upstream stop");
});
test("real HTTP producer disconnection is joined after one mapped request", { timeout: 5000 }, async t => {
  const disconnected = deferred(); let requests = 0;
  const server = createServer((request, response) => {
    requests++; request.on("close", disconnected.resolve); response.writeHead(200); response.write("descriptor");
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const abort = new AbortController(); let h, reader, ownerRetired = false; const terminal = deferred();
  t.after(async () => { abort.abort(); server.closeAllConnections(); terminal.resolve(ok(undefined)); if (h) await h.cancel(); await new Promise(resolve => server.close(resolve)); });
  const response = await fetch(`http://127.0.0.1:${server.address().port}`, { signal: abort.signal }); reader = response.body.getReader();
  const stream = new ReadableStream({ async pull(c) { const next = await reader.read(); if (next.done) c.close(); else c.enqueue(next.value); }, async cancel() { await reader.cancel(); } }, { highWaterMark: 0 });
  let retire;
  const owner = { readable: stream, closed: terminal.promise, cancel() { return retire ??= (async () => {
    await reader.cancel(); abort.abort(); await disconnected.promise; ownerRetired = true; terminal.resolve(cancelled()); return ok(undefined);
  })(); } };
  const result = api.mapFetchRequests(owner, value => ({ url: `https://example.test/${value.length}` })); assert.equal(result.outcome, "ok"); h = result.value;
  for await (const request of h.readable) { assert.match(request.url, /descriptor|10$/); break; }
  assert.equal(ownerRetired, true); assert.equal(requests, 1); assert.equal((await h.closed).outcome, "cancelled");
});
