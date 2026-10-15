/** Actual mapper and unchanged record decoders; native Streams/native loopback fetch.
 * The fetch-handle terminal adapter and imported request limits are explicit doubles.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";
const names = ["fetch-request-map", "fetch-records", "fetch-events"];
const sources = Object.fromEntries(names.map(name => [name, readFileSync(name === "fetch-request-map" && process.env.ASUPERSYNC_REQUEST_MAP_SOURCE
  ? process.env.ASUPERSYNC_REQUEST_MAP_SOURCE : new URL(`../packages/browser/src/${name}.ts`, import.meta.url), "utf8")]));
console.log(JSON.stringify({ scenario: "bounded-request-expansion", sha256: Object.fromEntries(Object.entries(sources).map(([n,s]) => [n,createHash("sha256").update(s).digest("hex")])),
  scope: "actual mapping/record code; native streams/fetch; explicit handle/terminal/limit doubles" }));
const context = createContext({ ReadableStream, ReadableStreamDefaultReader, AbortController, TextDecoder, Uint8Array });
const modules = Object.fromEntries(names.map(n => [n, new SourceTextModule(stripTypeScriptTypes(sources[n], { mode: "transform" }), { context })]));
const limits = new SyntheticModule(["BROWSER_FETCH_LIMITS"], function () { this.setExport("BROWSER_FETCH_LIMITS", { maxChunkBytes: 1_048_576 }); }, { context });
for (const module of Object.values(modules)) if (module.status === "unlinked") await module.link(name => {
  if (name === "./fetch.js") return limits;
  const result = modules[name.replace("./", "").replace(".js", "")]; assert.ok(result, name); return result;
});
for (const module of Object.values(modules)) await module.evaluate();
const api = modules["fetch-request-map"].namespace, events = modules["fetch-events"].namespace;
// Pre-feature control exercises the same consumers with the single-item API.
const flat = api.flatMapFetchRequests ?? api.mapFetchRequests;
const tryFlat = api.tryFlatMapFetchRequests ?? api.tryMapFetchRequests;
const ok = value => ({ outcome: "ok", value });
const err = message => ({ outcome: "err", failure: { code: "decode_failure", recoverability: "permanent", message } });
const cancelled = () => ({ outcome: "cancelled", cancellation: { kind: "test", phase: "completed", origin_region: "source",
  origin_task: null, timestamp_nanos: 0, message: "retired", truncated: false } });
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
async function pending(p) { let done = false; void p.then(() => { done = true; }, () => { done = true; }); await turn(); assert.equal(done, false); }
function input(t, values = [1, 2, 3]) {
  let pulls = 0, cancels = 0; const handles = [], gates = []; let pos = 0;
  const readable = new ReadableStream({ pull(c) { pulls++; if (pos < values.length) c.enqueue(values[pos++]); else c.close(); }, cancel() { cancels++; } }, { highWaterMark: 0 });
  function start(mapper, options, typed = false) {
    const result = (typed ? tryFlat : flat)(readable, mapper, options); assert.equal(result.outcome, "ok"); handles.push(result.value); return result.value;
  }
  t.after(async () => { for (const release of gates) release(); await Promise.all(handles.map(h => h.cancel("fixture cleanup"))); });
  return { readable, start, gates, get pulls() { return pulls; }, get cancels() { return cancels; } };
}
const consume = async h => { const result = []; for await (const value of h.readable) result.push(value.url); return result; };

test("bounded fan-out APIs are exported", () => { assert.equal(typeof api.flatMapFetchRequests, "function"); assert.equal(typeof api.tryFlatMapFetchRequests, "function"); });
for (const typed of [false, true]) {
  test(`fan-out preserves order and reads no next input while siblings remain (${typed})`, async t => {
    const f = input(t), h = f.start(v => { const result = [0, 1, 2].map(n => ({ url: `${v}/${n}` })); return typed ? ok(result) : result; }, { maxRequestsPerInput: 3 }, typed);
    const r = h.readable.getReader(); t.after(() => r.releaseLock()); await turn(); assert.equal(f.pulls, 0);
    for (let v = 1; v <= 3; v++) for (let n = 0; n < 3; n++) {
      assert.equal((await r.read()).value.url, `${v}/${n}`); await turn(); assert.equal(f.pulls, v);
    }
    assert.equal((await r.read()).done, true); assert.equal((await h.closed).outcome, "ok");
  });
  test(`empty expansion skips inputs without renumbering mapper indices (${typed})`, async t => {
    const f = input(t), indices = [], h = f.start((v, i) => {
      indices.push(i); const result = i === 1 ? [{ url: `${v}` }] : []; return typed ? ok(result) : result;
    }, {}, typed);
    assert.deepEqual(await consume(h), ["2"]); assert.deepEqual(indices, [0, 1, 2]); assert.equal((await h.closed).outcome, "ok");
  });
}
test("expansion list is snapshotted before publication, without using its iterator", async t => {
  const f = input(t, [1]), first = { url: "first" }, second = { url: "second" }, list = [first, second];
  list[Symbol.iterator] = () => assert.fail("untrusted iterator");
  const h = f.start(() => list), r = h.readable.getReader(); t.after(() => r.releaseLock());
  assert.equal((await r.read()).value, first); list[1] = { url: "changed" }; list.push({ url: "extra" });
  assert.equal((await r.read()).value, second); assert.equal((await r.read()).done, true);
});
for (const bad of [null, {}, new Set(), [undefined], [{ url: "not emitted" }, 7], new Array(2)]) {
  test(`invalid expansion ${JSON.stringify(bad)} emits no prefix`, async t => {
    const f = input(t), h = f.start(() => bad), r = h.readable.getReader(); t.after(() => r.releaseLock());
    await assert.rejects(r.read()); assert.equal((await h.closed).failure.code, "compatibility_rejected"); assert.equal(f.pulls, 1);
  });
}
test("oversized expansion refuses before reading its element getters", async t => {
  const f = input(t), list = new Array(3); let elements = 0;
  Object.defineProperty(list, "0", { get() { elements++; return { url: "never" }; } });
  const h = f.start(() => list, { maxRequestsPerInput: 2 }), r = h.readable.getReader(); t.after(() => r.releaseLock());
  await assert.rejects(r.read()); assert.equal(elements, 0); assert.equal((await h.closed).outcome, "err");
});
test("maxRequestsPerInput is checked before source ownership", async t => {
  const f = input(t);
  for (const maxRequestsPerInput of [0, -1, 1.5, 1025, Infinity, NaN, "2"]) {
    assert.equal(flat(f.readable, () => [], { maxRequestsPerInput }).outcome, "err");
    assert.equal(f.readable.locked, false);
  }
  assert.equal(f.pulls, 0); assert.equal(f.cancels, 0);
});
test("default cap is 64 and explicitly allowed 1024 expands without pulling ahead", async t => {
  for (const [size, options, success] of [[65, {}, false], [1024, { maxRequestsPerInput: 1024 }, true]]) {
    const f = input(t, [1]), h = f.start(() => Array.from({ length: size }, (_, n) => ({ url: `${n}` })), options);
    if (success) { const values = await consume(h); assert.equal(values.length, 1024); assert.equal(values[1023], "1023"); }
    else await assert.rejects(consume(h));
    assert.equal((await h.closed).outcome, success ? "ok" : "err");
  }
});
test("cancellation during indexed snapshot fences remaining getters and output", async t => {
  const f = input(t); let h, touched = 0; const list = [{ url: "first" }, { url: "second" }];
  Object.defineProperty(list, "0", { get() { void h.cancel("snapshot cancelled"); return { url: "never" }; } });
  Object.defineProperty(list, "1", { get() { touched++; return { url: "never" }; } });
  h = f.start(() => list); const r = h.readable.getReader(); t.after(() => r.releaseLock());
  await assert.rejects(r.read()); assert.equal((await h.closed).outcome, "cancelled"); assert.equal(touched, 0);
});
test("cancelling a partly delivered expansion discards siblings without touching their bodies", async t => {
  const f = input(t), body = new ReadableStream({ cancel() { assert.fail("unadmitted body acquired"); } });
  const h = f.start(v => [{ url: `${v}/a` }, { url: `${v}/b`, get body() { assert.fail("unadmitted body probed"); } }]);
  for await (const item of h.readable) { assert.equal(item.url, "1/a"); break; }
  assert.equal(f.pulls, 1); assert.equal(f.cancels, 1); assert.equal((await h.closed).outcome, "cancelled");
  assert.equal(body.locked, false);
});
test("every skipped expansion counts toward maxInputs", async t => {
  const f = input(t), mapped = [], h = f.start((v, i) => { mapped.push(i); return []; }, { maxInputs: 2 });
  await assert.rejects(consume(h)); assert.deepEqual(mapped, [0, 1]); assert.match((await h.closed).failure.message, /maxInputs/);
});
test("typed application failure after a delivered expansion preserves its exact cause", async t => {
  const f = input(t), h = f.start(v => v === 1 ? ok([{ url: "committed" }]) : err("cannot expand second"), {}, true);
  const r = h.readable.getReader(); t.after(() => r.releaseLock()); assert.equal((await r.read()).value.url, "committed");
  await assert.rejects(r.read()); assert.equal((await h.closed).failure.message, "cannot expand second"); assert.equal(f.pulls, 2);
});
for (const latePanic of [false, true]) {
  test(`two actual mapping stages join a parked upstream mapper (${latePanic})`, async t => {
    const f = input(t), started = deferred(), release = deferred(); f.gates.push(release.resolve); let signal;
    const admitted = api.tryMapFetchRequests(f.readable, async (_v, _i, s) => {
      signal = s; started.resolve(); await release.promise;
      return latePanic ? { outcome: "panicked", message: "late upstream panic" } : ok({ url: "late upstream" });
    }); assert.equal(admitted.outcome, "ok"); const upstream = admitted.value;
    const result = flat(upstream, request => [request, { url: "other" }]); assert.equal(result.outcome, "ok"); const downstream = result.value;
    t.after(async () => { release.resolve(); await downstream.cancel(); });
    const reader = downstream.readable.getReader(); t.after(() => reader.releaseLock()); const read = reader.read(); void read.catch(() => {});
    await started.promise; const done = downstream.cancel(); await pending(done); assert.equal(signal.aborted, true);
    await pending(upstream.closed); release.resolve(); const final = await done;
    assert.equal(final.outcome, latePanic ? "panicked" : "cancelled"); assert.equal((await upstream.closed).outcome, final.outcome);
    await assert.rejects(read); assert.equal(f.cancels, 1);
  });
}
function recordOwner(t, text, mime) {
  const terminal = deferred(); let sent = false, cancels = 0;
  const stream = new ReadableStream({ pull(c) {
    if (!sent) { sent = true; c.enqueue(new TextEncoder().encode(text)); }
    else { c.close(); terminal.resolve(ok(undefined)); }
  }, cancel() { cancels++; terminal.resolve(cancelled()); } }, { highWaterMark: 0 });
  const handle = { closed: terminal.promise, response: async () => ok({ status: 200, statusText: "", url: "https://example.test/", headers: [["content-type", mime]] }),
    toReadableStream: () => ok(stream), cancel: () => stream.cancel().then(() => ok(undefined)) };
  t.after(async () => { if (!stream.locked) await stream.cancel(); });
  return { handle, get cancels() { return cancels; } };
}
test("actual NDJSON decoder feeds bounded request expansion without an ownership bridge", async t => {
  const f = recordOwner(t, '{"ids":["a","b"]}\n{"ids":[]}\n{"ids":["c"]}\n', "application/x-ndjson");
  const decoded = events.jsonLines(f.handle); assert.equal(decoded.outcome, "ok");
  const expanded = flat(decoded.value, ({ value }) => value.ids.map(id => ({ url: `https://example.test/${id}` })));
  assert.equal(expanded.outcome, "ok"); t.after(() => expanded.value.cancel());
  assert.deepEqual(await consume(expanded.value), ["https://example.test/a", "https://example.test/b", "https://example.test/c"]);
  assert.equal((await decoded.value.closed).outcome, "ok"); assert.equal((await expanded.value.closed).outcome, "ok");
});
test("actual SSE decoder retains committed ID and is joined on expansion exit", async t => {
  const f = recordOwner(t, 'id: 7\ndata: one\n\nid: 8\ndata: unread\n\n', "text/event-stream");
  const decoded = events.serverSentEvents(f.handle); assert.equal(decoded.outcome, "ok");
  const expanded = flat(decoded.value, event => [{ url: `${event.lastEventId}/a` }, { url: `${event.lastEventId}/b` }]); assert.equal(expanded.outcome, "ok");
  t.after(() => expanded.value.cancel()); for await (const item of expanded.value.readable) { assert.equal(item.url, "7/a"); break; }
  assert.equal(decoded.value.lastEventId, "7"); assert.equal((await decoded.value.closed).outcome, "cancelled"); assert.equal(f.cancels, 1);
});
test("record decode failure propagates through expansion as decode_failure, not generic stream error", async t => {
  const f = recordOwner(t, 'invalid JSON\n', "application/x-ndjson"); const decoded = events.jsonLines(f.handle);
  assert.equal(decoded.outcome, "ok"); const expanded = flat(decoded.value, () => assert.fail("no valid record")); assert.equal(expanded.outcome, "ok");
  t.after(() => expanded.value.cancel()); await assert.rejects(consume(expanded.value));
  assert.equal((await expanded.value.closed).failure.code, "decode_failure");
});
test("real HTTP NDJSON feed expands to native child requests and early exit disconnects the feed", { timeout: 5000 }, async t => {
  const disconnected = deferred(), seen = []; const server = createServer((req, res) => {
    seen.push(req.url);
    if (req.url === "/feed") { req.on("close", disconnected.resolve); res.writeHead(200, { "content-type": "application/x-ndjson" }); res.write('{"ids":["a","b","c"]}\n'); }
    else res.end(req.url);
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`, abort = new AbortController(), completion = deferred(); let expanded;
  t.after(async () => { abort.abort(); server.closeAllConnections(); completion.resolve(ok(undefined)); if (expanded) await expanded.cancel(); await new Promise(resolve => server.close(resolve)); });
  const response = await fetch(`${origin}/feed`, { signal: abort.signal }); const raw = response.body.getReader();
  const body = new ReadableStream({ async pull(c) {
    try { const next = await raw.read(); if (next.done) { c.close(); completion.resolve(ok(undefined)); } else c.enqueue(next.value); }
    catch (error) { c.error(error); completion.resolve(err("native read failed")); }
  }, async cancel() { await raw.cancel(); abort.abort(); await disconnected.promise; completion.resolve(cancelled()); } }, { highWaterMark: 0 });
  const handle = { closed: completion.promise, response: async () => ok({ status: response.status, statusText: response.statusText, url: response.url, headers: [...response.headers] }),
    toReadableStream: () => ok(body), cancel: () => body.cancel().then(() => ok(undefined)) };
  const records = events.jsonLines(handle); assert.equal(records.outcome, "ok");
  const mapped = flat(records.value, ({ value }) => value.ids.map(id => ({ url: `${origin}/${id}` }))); assert.equal(mapped.outcome, "ok"); expanded = mapped.value;
  for await (const request of expanded.readable) { assert.equal(await (await fetch(request.url)).text(), "/a"); break; }
  assert.deepEqual(seen, ["/feed", "/a"]); await disconnected.promise;
  assert.equal((await records.value.closed).outcome, "cancelled"); assert.equal((await expanded.closed).outcome, "cancelled");
});
