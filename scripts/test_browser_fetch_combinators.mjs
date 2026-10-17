/** Real SDK fetch and combinators, native streams and loopback HTTP.
 * The task ABI is an explicit double; this is not Rust/WASM integration evidence.
 * Run: node --experimental-vm-modules --test scripts/test_browser_fetch_combinators.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";
const sources = Object.fromEntries(["fetch", "fetch-combinators"].map((name) => [name,
  readFileSync(name === "fetch-combinators" && process.env.ASUPERSYNC_FETCH_COMBINATORS_SOURCE
    ? process.env.ASUPERSYNC_FETCH_COMBINATORS_SOURCE : new URL(`../packages/browser/src/${name}.ts`, import.meta.url), "utf8")]));
console.log(JSON.stringify({ scenario_id: "browser-fetch-drained-combinators",
  source_sha256: Object.fromEntries(Object.entries(sources).map(([key, source]) => [key, createHash("sha256").update(source).digest("hex")])),
  evidence_scope: "actual SDK fetch/combinators; native Streams; loopback HTTP; task-ABI double" }));
const ok = (value) => ({ outcome: "ok", value });
const error = (message) => ({ outcome: "err", failure: { code: "internal_failure", recoverability: "permanent", message } });
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const turn = () => new Promise((resolve) => setImmediate(resolve));
async function pending(promise) { let settled = false; void promise.then(() => { settled = true; }); await turn(); assert.equal(settled, false); }

async function fixture(t, options = {}) {
  const calls = { fetch: [], cancel: [], join: [] }, handles = [], cleanup = [];
  let next = 0;
  class Handle { constructor(raw) { this.raw = raw; } toJSON() { return { ...this.raw }; } }
  const exports = {
    Outcome: { ok, err: (code, recoverability, message) => ({ outcome: "err", failure: { code, recoverability, message } }), cancelled: (cancellation) => ({ outcome: "cancelled", cancellation }) },
    RegionHandle: Handle,
    taskSpawn: () => ok(new Handle({ kind: "task", slot: ++next, generation: 1, owner_token: "owner" })),
    taskCancel(request) { calls.cancel.push(request); return options.cancel?.(request) ?? ok(undefined); },
    taskJoin(task, outcome) { calls.join.push({ task, outcome }); return options.join?.(task, outcome) ?? outcome; },
  };
  const context = createContext({ URL, ArrayBuffer, DataView, Uint8Array, AbortSignal, EventTarget, Request, Blob,
    ReadableStream, ReadableStreamDefaultReader, ...options.globals });
  const abi = new SyntheticModule(Object.keys(exports), function () { for (const [name, value] of Object.entries(exports)) this.setExport(name, value); }, { context });
  const modules = Object.fromEntries(Object.entries(sources).map(([name, source]) => [name,
    new SourceTextModule(stripTypeScriptTypes(source, { mode: "transform" }), { context, identifier: name })]));
  for (const module of Object.values(modules)) if (module.status === "unlinked") await module.link((name) => name === "@asupersync/browser-core" ? abi : modules[name.replace(/^\.\//, "").replace(/\.js$/, "")]);
  await modules["fetch-combinators"].evaluate();
  const origin = options.origin ?? "https://example.test";
  const { createBrowserFetchManager, prepareBrowserFetchAuthority, browserFetchHandleKey } = modules.fetch.namespace;
  const scope = new Handle({ kind: "region", slot: 1, generation: 1, owner_token: "owner" });
  const scopeKey = browserFetchHandleKey(scope.toJSON());
  const grant = { rootKey: "root", authority: prepareBrowserFetchAuthority({ allowedOrigins: [origin], allowedMethods: ["GET", "POST"], maxHeaderCount: 2 }) };
  const host = { AbortController, setTimeout, clearTimeout,
    fetch(url, init) { calls.fetch.push({ url, init }); return options.fetch?.(url, init, calls.fetch.length - 1) ?? new Promise((resolve, reject) => {
      if (init.signal.aborted) reject(new Error("aborted"));
      else init.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
    }); },
  };
  const manager = createBrowserFetchManager({ lookup: (key) => key === scopeKey ? grant : null, isClosing: () => false, globalObject: () => host });
  const start = (extra = {}) => { const admitted = manager.start(scope, { url: `${origin}/${handles.length}`, ...extra }, null); assert.equal(admitted.outcome, "ok"); handles.push(admitted.value); return admitted.value; };
  t.after(async () => { for (const release of cleanup) release(); manager.closeScopes(new Set([scopeKey]), "test_cleanup"); await Promise.all(handles.map((handle) => handle.closed)); });
  return { start, calls, cleanup, manager, scopeKey, ...modules["fetch-combinators"].namespace,
    join(list) { const admitted = modules["fetch-combinators"].namespace.joinFetchResponses(list); assert.equal(admitted.outcome, "ok"); return admitted.value; },
    race(list) { const admitted = modules["fetch-combinators"].namespace.raceFetchResponses(list); assert.equal(admitted.outcome, "ok"); return admitted.value; } };
}
function body(bytes = [1], counters = {}) {
  let sent = false;
  return new ReadableStream({ pull(controller) {
    counters.pulls = (counters.pulls ?? 0) + 1;
    if (sent) controller.close(); else { sent = true; controller.enqueue(Uint8Array.from(bytes)); }
  }, cancel() { counters.cancels = (counters.cancels ?? 0) + 1; return counters.cleanup; } }, { highWaterMark: 0 });
}

for (const input of [null, {}, [], new Array(65).fill({})]) test(`invalid bounded member array ${String(input)}`, { timeout: 3000 }, async (t) => {
  const f = await fixture(t); assert.equal(f.raceFetchResponses(input).outcome, "err"); assert.equal(f.calls.cancel.length, 0);
});
test("duplicate handles refuse before any body conversion", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { fetch: () => new Response(Uint8Array.of(7)) }); const handle = f.start();
  assert.equal(f.raceFetchResponses([handle, handle]).outcome, "err"); assert.equal((await handle.read()).outcome, "ok");
});
test("setup rollback releases earlier locks without cancelling members", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { fetch: () => new Response(Uint8Array.of(7)) }); const a = f.start(), b = f.start();
  const locked = b.toReadableStream().value.getReader();
  assert.equal(f.raceFetchResponses([a, b]).outcome, "err");
  assert.equal(a.toReadableStream().value.locked, false); assert.equal(f.calls.cancel.length, 0);
  locked.releaseLock(); assert.deepEqual(Array.from(await new Response(a.toReadableStream().value).bytes()), [7]);
});
test("aliased bodies refuse and release the acquired lock", { timeout: 3000 }, async (t) => {
  const f = await fixture(t); const a = f.start(); const alias = { ...a };
  assert.equal(f.raceFetchResponses([a, alias]).outcome, "err"); assert.equal(a.toReadableStream().value.locked, false);
});
test("missing native readers refuses without taking ownership", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { globals: { ReadableStreamDefaultReader: undefined } }); const a = f.start();
  assert.equal(f.raceFetchResponses([a]).outcome, "err"); assert.equal(f.calls.cancel.length, 0);
});
test("winner body is not prefetched; parked loser is cancelled and joined", { timeout: 3000 }, async (t) => {
  const count = {}; const f = await fixture(t, { fetch: (_url, _init, index) => index === 1 ? new Response(body([8, 9], count)) : undefined });
  const a = f.start(), b = f.start(); const race = f.race([a, b]); const won = await race.result;
  assert.equal(won.outcome, "ok"); assert.equal(won.value.index, 1); assert.equal(count.pulls ?? 0, 0);
  assert.equal((await a.closed).outcome, "cancelled"); assert.equal(f.calls.join.length, 1); assert.equal(won.value.fetch, b);
  assert.equal(won.value.body.locked, false); assert.equal(b.toReadableStream().value, won.value.body);
  assert.deepEqual(Array.from(await new Response(won.value.body).bytes()), [8, 9]); assert.equal((await b.closed).outcome, "ok");
});
test("ready response ties use input order; HTTP errors are ordinary responses", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { fetch: () => new Response(null, { status: 404 }) }); const a = f.start(), b = f.start();
  await Promise.all([a.response(), b.response()]); const won = await f.race([b, a]).result;
  assert.equal(won.outcome, "ok"); assert.equal(won.value.index, 0); assert.equal(won.value.fetch, b); assert.equal(won.value.response.status, 404);
});
test("late abort-insensitive response is disposed before the winner transfers", { timeout: 3000 }, async (t) => {
  const late = deferred(), cleaned = deferred(), count = { cleanup: cleaned.promise }, winnerCount = {};
  const f = await fixture(t, { fetch: (_url, _init, index) => index ? new Response(body([2], winnerCount)) : late.promise });
  const response = new Response(body([1], count)); f.cleanup.push(() => late.resolve(response), cleaned.resolve);
  const a = f.start(), b = f.start(); const race = f.race([a, b]); await pending(race.result);
  assert.equal(b.toReadableStream().value.locked, true); late.resolve(response); await pending(race.result);
  assert.equal(count.cancels, 1); assert.equal(winnerCount.pulls ?? 0, 0); assert.equal(f.calls.join.length, 0);
  cleaned.resolve(); assert.equal((await race.result).outcome, "ok"); assert.equal(f.calls.join.length, 1);
});
test("loser cleanup starts in parallel and waits for every member", { timeout: 3000 }, async (t) => {
  const gates = [deferred(), deferred()]; const counts = gates.map((gate) => ({ cleanup: gate.promise }));
  const f = await fixture(t, { fetch: (_url, _init, index) => new Response(index ? body([index], counts[index - 1]) : null) });
  f.cleanup.push(...gates.map((gate) => gate.resolve)); const handles = [f.start(), f.start(), f.start()]; await Promise.all(handles.map((handle) => handle.response()));
  const race = f.race(handles); await pending(race.result); assert.deepEqual(counts.map((count) => count.cancels), [1, 1]);
  gates[0].resolve(); await pending(race.result); gates[1].resolve(); assert.equal((await race.result).outcome, "ok");
});
test("first network failure cancels every parked sibling", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { fetch: (_url, _init, index) => index === 1 ? Promise.reject(new Error("network-down")) : undefined });
  const handles = [f.start(), f.start(), f.start()]; const outcome = await f.race(handles).result;
  assert.equal(outcome.outcome, "err"); assert.match(outcome.failure.message, /network-down/); assert.equal(f.calls.join.length, 3);
  assert.equal(f.calls.fetch.every(({ init }) => init.signal.aborted), true);
});
test("group cancellation is idempotent and does not abort caller-owned signals", { timeout: 3000 }, async (t) => {
  const f = await fixture(t); const controller = new AbortController(); const race = f.race([f.start({ signal: controller.signal }), f.start()]);
  const first = race.cancel("stop group"), second = race.cancel("ignored"); assert.equal(first, second);
  const outcome = await first; assert.equal(outcome.outcome, "cancelled"); assert.equal(outcome.cancellation.message, "stop group");
  assert.equal((await race.result).outcome, "cancelled"); assert.equal(controller.signal.aborted, false); assert.equal(f.calls.join.length, 2);
});
test("invalid cancellation reason does not stop the race", { timeout: 3000 }, async (t) => {
  const f = await fixture(t); const race = f.race([f.start()]); assert.equal((await race.cancel({})).outcome, "err");
  assert.equal(f.calls.cancel.length, 0); await race.cancel();
});
test("successful transfer makes later group cancellation inert", { timeout: 3000 }, async (t) => {
  const count = {}; const f = await fixture(t, { fetch: () => new Response(body([4], count)) }); const winner = f.start();
  const race = f.race([winner]); const selected = await race.result; assert.equal(selected.outcome, "ok");
  assert.equal((await race.cancel()).outcome, "ok"); assert.equal(count.cancels ?? 0, 0);
  assert.deepEqual(Array.from(await new Response(selected.value.body).bytes()), [4]);
});
test("caller cancellation while draining also retires the selected winner", { timeout: 3000 }, async (t) => {
  const gate = deferred(), counts = [{}, { cleanup: gate.promise }];
  const f = await fixture(t, { fetch: (_url, _init, index) => new Response(body([index], counts[index])) }); f.cleanup.push(gate.resolve);
  const a = f.start(), b = f.start(); await Promise.all([a.response(), b.response()]); const race = f.race([a, b]); await pending(race.result);
  const cancelled = race.cancel("during drain"); await pending(cancelled); assert.equal(counts[0].cancels, 1); gate.resolve();
  assert.equal((await race.result).outcome, "cancelled"); assert.equal(f.calls.join.length, 2);
});
test("winner failure during loser drain cannot transfer a dead body", { timeout: 3000 }, async (t) => {
  const gate = deferred(); let controller;
  const f = await fixture(t, { fetch: (_url, _init, index) => new Response(index
    ? body([2], { cleanup: gate.promise }) : new ReadableStream({ start(value) { controller = value; } })) }); f.cleanup.push(gate.resolve);
  const a = f.start(), b = f.start(); await Promise.all([a.response(), b.response()]); const race = f.race([a, b]); await pending(race.result);
  controller.error(new Error("winner-reset")); gate.resolve(); const outcome = await race.result;
  assert.equal(outcome.outcome, "err"); assert.match(outcome.failure.message, /winner-reset/); assert.equal(f.calls.join.length, 2);
});
test("scope cancellation reaches a race with every branch parked", { timeout: 3000 }, async (t) => {
  const f = await fixture(t); const race = f.race([f.start(), f.start()]);
  f.manager.closeScopes(new Set([f.scopeKey]), "scope_close"); assert.equal((await race.result).outcome, "cancelled");
  assert.equal(f.calls.fetch.every(({ init }) => init.signal.aborted), true);
});
test("loser ABI cancellation refusal fails the race and retires the winner", { timeout: 3000 }, async (t) => {
  const count = {}; const f = await fixture(t, { fetch: (_url, _init, index) => index ? undefined : new Response(body([1], count)),
    cancel: (request) => request.task.toJSON().slot === 2 ? error("cancel-refused") : undefined });
  const result = await f.race([f.start(), f.start()]).result; assert.equal(result.outcome, "err"); assert.match(result.failure.message, /cancel-refused/);
  assert.equal(count.cancels, 1); assert.equal(f.calls.join.length, 2);
});
test("publication refusal keeps runtime capacity and cannot become race success", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { fetch: (_url, _init, index) => index ? undefined : new Response(body()),
    join: (task) => task.toJSON().slot === 2 ? error("join-refused") : undefined });
  const result = await f.race([f.start(), f.start()]).result; assert.equal(result.outcome, "err"); assert.match(result.failure.message, /join-refused/);
  for (let index = 0; index < 63; index += 1) f.start();
  assert.throws(() => f.start(), /err.*ok/s, "retained failed task still consumes its admission credit");
});
test("group does not cancel unrelated work in the same scope", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { fetch: (_url, _init, index) => index === 1 ? new Response(null) : undefined });
  const unrelated = f.start(); assert.equal((await f.race([f.start(), f.start()]).result).outcome, "ok");
  assert.equal(f.calls.fetch[0].init.signal.aborted, false); await unrelated.cancel();
});
test("a reentrant cancellation hook cannot duplicate retirement or lose the winner", { timeout: 3000 }, async (t) => {
  let race; const f = await fixture(t, { fetch: (_url, _init, index) => index ? undefined : new Response(body()),
    cancel() { void race?.cancel("reentrant stop"); } }); race = f.race([f.start(), f.start()]);
  assert.equal((await race.result).outcome, "cancelled"); assert.equal(f.calls.cancel.length, 2); assert.equal(f.calls.join.length, 2);
});
test("live HTTP race retires the stalled loser and disconnects the peer", { timeout: 5000 }, async (t) => {
  const loserArrived = deferred(), disconnected = deferred(); let requests = 0;
  const server = createServer((request, response) => {
    requests += 1;
    if (request.url === "/0") { response.on("close", disconnected.resolve); loserArrived.resolve(); }
    else void loserArrived.promise.then(() => { response.writeHead(200); response.end("winner"); });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); });
  const f = await fixture(t, { origin: `http://127.0.0.1:${server.address().port}`, fetch: (url, init) => fetch(url, init) });
  const won = await f.race([f.start(), f.start()]).result;
  assert.equal(won.outcome, "ok"); assert.equal(won.value.index, 1); assert.equal(await new Response(won.value.body).text(), "winner");
  await disconnected.promise; assert.equal(requests, 2); assert.equal(f.calls.join.length, 2);
});

for (const invalid of [null, 1, { outcome: "bogus" }, { outcome: "err", failure: null }]) {
  test(`malformed asynchronous outcome fails and drains: ${String(invalid)}`, { timeout: 3000 }, async (t) => {
    const f = await fixture(t); const handle = f.start();
    const wrapped = { ...handle, response: () => Promise.resolve(invalid) };
    const result = await f.race([wrapped]).result;
    assert.equal(result.outcome, "err"); assert.match(result.failure.message, /invalid fetch group outcome/);
    assert.equal((await handle.closed).outcome, "cancelled");
  });
}
test("throwing response method is contained after ownership transfer", { timeout: 3000 }, async (t) => {
  const f = await fixture(t); const handle = f.start();
  const result = await f.race([{ ...handle, response() { throw new Error("private payload"); } }]).result;
  assert.equal(result.outcome, "err"); assert.match(result.failure.message, /response threw/);
  assert.equal(result.failure.message.includes("private payload"), false); assert.equal(f.calls.join.length, 1);
});

test("join returns all headers in input order without reading any body", { timeout: 3000 }, async (t) => {
  const delivered = [deferred(), deferred(), deferred()], counts = [{}, {}, {}];
  const responses = counts.map((count, index) => new Response(body([index], count), { status: 200 + index }));
  const f = await fixture(t, { fetch: (_url, _init, index) => delivered[index].promise });
  f.cleanup.push(...delivered.map((item, index) => () => item.resolve(responses[index])));
  const handles = [f.start(), f.start(), f.start()]; const joined = f.join(handles);
  delivered[2].resolve(responses[2]); delivered[0].resolve(responses[0]); await pending(joined.result);
  assert.equal(handles[0].toReadableStream().value.locked, true); delivered[1].resolve(responses[1]);
  const result = await joined.result; assert.equal(result.outcome, "ok"); assert.equal(Object.isFrozen(result.value), true);
  assert.deepEqual(Array.from(result.value, (item) => item.index), [0, 1, 2]); assert.deepEqual(counts.map((count) => count.pulls ?? 0), [0, 0, 0]);
  assert.equal(f.calls.cancel.length, 0); assert.equal(f.calls.join.length, 0);
  for (const item of result.value) { assert.equal(item.fetch, handles[item.index]); assert.equal(item.response.status, 200 + item.index); assert.deepEqual(Array.from(await new Response(item.body).bytes()), [item.index]); }
  assert.equal(f.calls.join.length, 3);
});
test("join of no requests is a successful identity without native reader support", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { globals: { ReadableStreamDefaultReader: undefined } }); const joined = f.join([]);
  assert.equal((await joined.cancel()).outcome, "ok"); const result = await joined.result;
  assert.equal(result.outcome, "ok"); assert.equal(result.value.length, 0); assert.equal(f.calls.fetch.length, 0);
  assert.equal((await joined.cancel(null)).outcome, "err");
});
test("join cancellation before headers joins all owned tasks", { timeout: 3000 }, async (t) => {
  const f = await fixture(t); const joined = f.join([f.start(), f.start(), f.start()]);
  const cancel = joined.cancel("cancel batch"); assert.equal(joined.cancel("ignored"), cancel);
  const result = await joined.result; assert.equal(result.outcome, "cancelled"); assert.equal(result.cancellation.kind, "fetch_join_cancel");
  assert.equal(result.cancellation.message, "cancel batch"); await cancel; assert.equal(f.calls.join.length, 3);
});
test("join fails fast on one request but waits for sibling cleanup", { timeout: 3000 }, async (t) => {
  const gate = deferred(); let cancelled = 0;
  const f = await fixture(t, { fetch: (_url, _init, index) => index === 1 ? Promise.reject(new Error("join-network-error"))
    : new Response(new ReadableStream({ cancel() { cancelled += 1; return gate.promise; } })) }); f.cleanup.push(gate.resolve);
  const joined = f.join([f.start(), f.start(), f.start()]); await pending(joined.result); assert.equal(cancelled, 2);
  gate.resolve(); const result = await joined.result; assert.equal(result.outcome, "err"); assert.match(result.failure.message, /join-network-error/);
  assert.equal(f.calls.join.length, 3);
});
test("join watches an already-ready body for failure while another header is parked", { timeout: 3000 }, async (t) => {
  let control; const f = await fixture(t, { fetch: (_url, _init, index) => index ? undefined
    : new Response(new ReadableStream({ start(controller) { control = controller; } })) });
  const a = f.start(), b = f.start(); await a.response(); const joined = f.join([a, b]); await pending(joined.result);
  control.error(new Error("ready-body-reset")); const result = await joined.result;
  assert.equal(result.outcome, "err"); assert.match(result.failure.message, /ready-body-reset/); assert.equal(f.calls.fetch[1].init.signal.aborted, true);
});
test("join disposes a late response body before reporting another member's failure", { timeout: 3000 }, async (t) => {
  const late = deferred(), gate = deferred(); let cancels = 0;
  const response = new Response(new ReadableStream({ cancel() { cancels += 1; return gate.promise; } }));
  const f = await fixture(t, { fetch: (_url, _init, index) => index ? late.promise : Promise.reject(new Error("early-error")) });
  f.cleanup.push(() => late.resolve(response), gate.resolve); const joined = f.join([f.start(), f.start()]); await pending(joined.result);
  late.resolve(response); await pending(joined.result); assert.equal(cancels, 1); gate.resolve(); assert.equal((await joined.result).outcome, "err");
});
test("join retains all bodies until every header is ready", { timeout: 3000 }, async (t) => {
  const delivered = deferred(), count = {}; const last = new Response(null);
  const f = await fixture(t, { fetch: (_url, _init, index) => index ? delivered.promise : new Response(body([5], count)) });
  f.cleanup.push(() => delivered.resolve(last)); const a = f.start(), b = f.start(); const joined = f.join([a, b]);
  await a.response(); await pending(joined.result); assert.equal(count.pulls ?? 0, 0); assert.equal(a.toReadableStream().value.locked, true);
  delivered.resolve(last); const result = await joined.result; assert.equal(result.outcome, "ok");
  assert.equal((await joined.cancel()).outcome, "ok"); assert.equal(count.cancels ?? 0, 0);
  await result.value[0].body.cancel(); assert.equal((await a.closed).outcome, "cancelled");
});
test("join member deadline cancels another parked request", { timeout: 3000 }, async (t) => {
  const f = await fixture(t); const joined = f.join([f.start({ timeoutMs: 1 }), f.start()]); const result = await joined.result;
  assert.equal(result.outcome, "cancelled"); assert.equal(result.cancellation.kind, "deadline"); assert.equal(f.calls.join.length, 2);
});
test("join scope teardown never leaves ready or pending requests behind", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { fetch: (_url, _init, index) => index ? undefined : new Response(body()) });
  const joined = f.join([f.start(), f.start()]); f.manager.closeScopes(new Set([f.scopeKey]), "scope_close");
  assert.equal((await joined.result).outcome, "cancelled"); assert.equal(f.calls.fetch.every(({ init }) => init.signal.aborted), true);
});
test("joined bodies compose into a new race without new tasks or requests", { timeout: 3000 }, async (t) => {
  const counts = [{}, {}]; const f = await fixture(t, { fetch: (_url, _init, index) => new Response(body([index], counts[index])) });
  const joined = await f.join([f.start(), f.start()]).result; assert.equal(joined.outcome, "ok");
  const won = await f.race(Array.from(joined.value, (item) => item.fetch)).result; assert.equal(won.outcome, "ok");
  assert.equal(won.value.index, 0); assert.equal(counts[1].cancels, 1); assert.equal(f.calls.fetch.length, 2);
  await new Response(won.value.body).bytes(); assert.equal(f.calls.join.length, 2);
});
test("join with one already-consumed prefix returns only the remaining bytes", { timeout: 3000 }, async (t) => {
  let index = 0; const f = await fixture(t, { fetch: () => new Response(new ReadableStream({ pull(c) {
    if (index < 2) c.enqueue(Uint8Array.of(++index)); else c.close();
  } }, { highWaterMark: 0 })) }); const handle = f.start(); assert.deepEqual(Array.from((await handle.read()).value.value), [1]);
  const joined = await f.join([handle]).result; assert.equal(joined.outcome, "ok");
  assert.deepEqual(Array.from(await new Response(joined.value[0].body).bytes()), [2]);
});
test("join preserves HTTP error statuses as successfully joined headers", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { fetch: (_url, _init, index) => new Response(null, { status: index ? 500 : 404 }) });
  const joined = await f.join([f.start(), f.start()]).result; assert.equal(joined.outcome, "ok");
  assert.deepEqual(Array.from(joined.value, (item) => item.response.status), [404, 500]);
});
test("join never hides a cleanup panic behind an earlier error", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { join: (task) => task.toJSON().slot === 1 ? error("first error") : { outcome: "panicked", message: "cleanup panic" } });
  const joined = f.join([f.start(), f.start()]); const result = await joined.cancel();
  assert.equal(result.outcome, "panicked"); assert.equal(result.message, "cleanup panic");
});
test("join cancellation/publication refusal cannot publish a partial result", { timeout: 3000 }, async (t) => {
  const f = await fixture(t, { fetch: (_url, _init, index) => index ? undefined : new Response(body()),
    cancel: (request) => request.task.toJSON().slot === 2 ? error("join cancellation refused") : undefined });
  const joined = f.join([f.start(), f.start()]); const result = await joined.cancel();
  // The caller's cancellation outranks the member's cleanup refusal (the
  // Outcome lattice, Panicked > Cancelled > Err), but the join still drains
  // both members and publishes no partial result.
  assert.equal(result.outcome, "cancelled"); assert.equal(result.cancellation.kind, "fetch_join_cancel");
  assert.equal(result.cancellation.message, "fetch join cancelled by caller");
  assert.ok(f.calls.cancel.some((request) => request.task.toJSON().slot === 2)); assert.equal(f.calls.join.length, 2);
});
test("join live HTTP headers overlap and both bodies remain independently consumable", { timeout: 5000 }, async (t) => {
  const arrivals = []; let requests = 0;
  const server = createServer((request, response) => {
    requests += 1; arrivals.push({ request, response });
    if (arrivals.length === 2) for (const { request: req, response: res } of arrivals) {
      res.writeHead(200, { "content-type": "text/plain" }); res.flushHeaders();
      setImmediate(() => res.end(`body:${req.url}`));
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); });
  const f = await fixture(t, { origin: `http://127.0.0.1:${server.address().port}`, fetch: (url, init) => fetch(url, init) });
  const result = await f.join([f.start(), f.start()]).result; assert.equal(result.outcome, "ok");
  assert.deepEqual(await Promise.all(Array.from(result.value, (item) => new Response(item.body).text())), ["body:/0", "body:/1"]);
  assert.equal(requests, 2); assert.equal(f.calls.cancel.length, 0); assert.equal(f.calls.join.length, 2);
});
