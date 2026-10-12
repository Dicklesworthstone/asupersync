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
    assert.equal(result.outcome, "err"); assert.match(result.failure.message, /invalid fetch race outcome/);
    assert.equal((await handle.closed).outcome, "cancelled");
  });
}
test("throwing response method is contained after ownership transfer", { timeout: 3000 }, async (t) => {
  const f = await fixture(t); const handle = f.start();
  const result = await f.race([{ ...handle, response() { throw new Error("private payload"); } }]).result;
  assert.equal(result.outcome, "err"); assert.match(result.failure.message, /response threw/);
  assert.equal(result.failure.message.includes("private payload"), false); assert.equal(f.calls.join.length, 1);
});
