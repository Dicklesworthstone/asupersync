/**
 * Browser SDK host-fetch streaming regressions (Node 24+):
 * node --experimental-vm-modules --test --test-concurrency=1 \
 *   scripts/test_browser_sdk_fetch_streams.mjs
 *
 * Executes the actual SDK, fetch adapter and core facade. Only the generated
 * WASM ABI is replaced with an intentional call recorder; fetch is a controlled
 * host returning native WHATWG Response/ReadableStream objects. One journey also
 * uses Node's actual fetch against a real, gated localhost HTTP server. The recorder
 * tracks live tasks and injects owner-close refusal until their terminal join;
 * a separate mode permits recursive release. These intentionally exercise ABI
 * result branches, not a complete model of Rust's close rules. Evidence covers
 * the JS host boundary and localhost HTTP integration, not packaged WASM,
 * browser integration or external-network interoperability.
 * No source file is rewritten by the harness.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";

const sdkPath = process.env.ASUPERSYNC_BROWSER_SDK_SOURCE
  ?? fileURLToPath(new URL("../packages/browser/src/index.ts", import.meta.url));
const fetchPath = process.env.ASUPERSYNC_BROWSER_FETCH_SOURCE
  ?? fileURLToPath(new URL("../packages/browser/src/fetch.ts", import.meta.url));
const corePath = process.env.ASUPERSYNC_BROWSER_CORE_SOURCE
  ?? fileURLToPath(new URL("../packages/browser-core/index.js", import.meta.url));
const managerPath = fileURLToPath(new URL("../packages/browser-core/webtransport-streams.js", import.meta.url));
const sources = {
  sdk: readFileSync(sdkPath, "utf8"), fetch: readFileSync(fetchPath, "utf8"),
  core: readFileSync(corePath, "utf8"), streams: readFileSync(managerPath, "utf8"),
};
const javaScript = {
  sdk: stripTypeScriptTypes(sources.sdk, { mode: "transform" }),
  fetch: stripTypeScriptTypes(sources.fetch, { mode: "transform" }),
};
console.log(JSON.stringify({
  scenario_id: "browser-sdk-owned-fetch-streams",
  source_sha256: Object.fromEntries(Object.entries(sources).map(([name, source]) => [
    name, createHash("sha256").update(source).digest("hex"),
  ])),
  evidence_scope: "actual SDK/fetch/core, native streams and localhost HTTP fetch, intentional WASM ABI ledger recorder",
  no_claim: ["Rust dispatcher execution", "packaged WASM", "browser integration", "external-network interoperability"],
}));

const clone = (value) => structuredClone(value);
const turn = () => new Promise((resolve) => setImmediate(resolve));
const unitJson = '{"outcome":"ok","value":{"kind":"unit"}}';
const requestUrl = "https://api.example.test/resource";
const liveTaskFailure = JSON.stringify({ outcome: "err", failure: {
  code: "compatibility_rejected", recoverability: "transient", message: "owner retains live tasks",
} });

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}
function unwrap(outcome) {
  assert.equal(outcome.outcome, "ok", JSON.stringify(outcome));
  return outcome.value;
}
function failure(outcome, code) {
  assert.equal(outcome.outcome, "err", JSON.stringify(outcome));
  if (code) assert.equal(outcome.failure.code, code);
  return outcome.failure;
}
function cancellation(outcome) {
  assert.equal(outcome.outcome, "cancelled", JSON.stringify(outcome));
  return outcome.cancellation;
}
function bytes(outcome) {
  const chunk = unwrap(outcome);
  assert.equal(chunk.done, false);
  return Array.from(chunk.value);
}
function handleMatches(recorded, actual) {
  const expected = actual.toJSON();
  assert.deepEqual({ ...recorded, owner_token: String(recorded.owner_token) }, {
    ...clone(expected), owner_token: String(expected.owner_token),
  });
}
function responseBody(options = {}) {
  let input;
  const events = [];
  const readable = new ReadableStream({
    start(controller) { input = controller; },
    pull() { events.push(["pull"]); return options.pull?.(); },
    cancel(reason) { events.push(["cancel", reason]); return options.cancel?.(reason); },
  }, { highWaterMark: 0 });
  return { readable, input, events };
}

async function fixture(t, options = {}) {
  const calls = { init: 0, runtimeCreate: [], scopeEnter: [], spawn: [], join: [], cancel: [],
    scopeClose: [], runtimeClose: [], rawFetch: [], network: [], issuedTasks: [], transports: [] };
  const controls = { scopeClose: null, runtimeClose: null, taskCancel: unitJson, taskJoin: null };
  const parents = new Map();
  const regions = new Map();
  const liveTasks = new Map();
  const handles = [];
  let nextRuntime = 1;
  let nextRegion = 100;
  let nextTask = 1;
  let nextFetch = 1000;
  const authority = options.authority ?? {
    allowedOrigins: ["https://api.example.test"], allowedMethods: ["GET", "POST"],
    allowCredentials: false, maxHeaderCount: 2,
  };
  const key = (raw) => [raw.kind, raw.slot, raw.generation, raw.owner_token].join(":");
  function ownedBy(scope, owner) {
    let current = key(scope);
    while (current !== undefined) {
      if (current === key(owner)) return true;
      current = parents.get(current);
    }
    return false;
  }
  function closeOwner(raw, override) {
    const hasLiveTasks = [...liveTasks.values()].some((scope) => ownedBy(scope, raw));
    const result = override ?? (!options.acceptLiveOwnerClose && hasLiveTasks ? liveTaskFailure : unitJson);
    if (JSON.parse(result).outcome === "ok") {
      const descendants = [...regions.values()].filter((region) => ownedBy(region, raw));
      for (const [task, scope] of liveTasks) if (ownedBy(scope, raw)) liveTasks.delete(task);
      for (const region of descendants) {
        parents.delete(key(region));
        regions.delete(key(region));
      }
    }
    return result;
  }

  function hostFetch(url, init) {
    if (options.actualFetch) {
      calls.network.push({ url: String(url), init, events: [], response: true });
      return options.actualFetch(url, init);
    }
    const headers = deferred();
    const events = [];
    const request = {
      url: String(url), init, events, headers,
      respond(body = responseBody(), responseOptions = {}) {
        request.body = body;
        const response = new Response(body === null ? null : body.readable, {
          status: responseOptions.status ?? 200,
          statusText: responseOptions.statusText ?? "OK",
          headers: responseOptions.headers ?? { "content-type": "application/octet-stream" },
        });
        Object.defineProperty(response, "url", { value: responseOptions.url ?? String(url) });
        if (responseOptions.redirected) Object.defineProperty(response, "redirected", { value: true });
        request.response = response;
        headers.resolve(response);
        return body;
      },
    };
    init.signal.addEventListener("abort", () => {
      events.push(["abort", init.signal.reason]);
      if (!options.ignoreAbort) headers.reject(new DOMException("fetch was aborted", "AbortError"));
    }, { once: true });
    calls.network.push(request);
    return headers.promise;
  }

  class ControlledTransport {
    constructor() {
      this.ready = Promise.resolve();
      this.completion = deferred();
      this.closed = this.completion.promise;
      this.closes = 0;
      this.datagrams = { readable: new ReadableStream(), writable: new WritableStream() };
      calls.transports.push(this);
    }
    close(info = {}) { this.closes += 1; this.completion.resolve(info); }
  }

  const context = createContext({
    AbortController, ArrayBuffer, Uint8Array, URL, TextEncoder, TextDecoder,
    ReadableStream, WritableStream, Response, Headers, Request, WebAssembly,
    Error, TypeError, RangeError, DOMException, structuredClone, queueMicrotask,
    setTimeout, clearTimeout, window: {}, document: {}, isSecureContext: true,
    fetch: hostFetch, WebTransport: ControlledTransport,
  });
  const names = [
    "default", "abi_fingerprint", "abi_version", "fetch_request",
    "runtime_close", "runtime_create", "scope_close", "scope_enter",
    "task_cancel", "task_join", "task_spawn", "websocket_cancel",
    "websocket_close", "websocket_open", "websocket_recv", "websocket_send",
  ];
  const handle = (kind, slot) => JSON.stringify({ kind, slot, generation: 1, owner_token: "42" });
  const implementations = {
    default: async () => { calls.init += 1; },
    abi_fingerprint: () => "4558451663113424898",
    abi_version: () => '{"major":1,"minor":0}',
    runtime_create: (request) => {
      calls.runtimeCreate.push(JSON.parse(request));
      return handle("runtime", nextRuntime++);
    },
    scope_enter: (request) => {
      const parsed = JSON.parse(request);
      calls.scopeEnter.push(parsed);
      const result = handle("region", nextRegion++);
      parents.set(key(JSON.parse(result)), key(parsed.parent));
      regions.set(key(JSON.parse(result)), JSON.parse(result));
      return result;
    },
    task_spawn: (request) => {
      const parsed = JSON.parse(request);
      calls.spawn.push(parsed);
      const result = handle("task", nextTask++);
      calls.issuedTasks.push(JSON.parse(result));
      liveTasks.set(key(JSON.parse(result)), parsed.scope);
      return result;
    },
    task_join: (task, outcome) => {
      const parsed = JSON.parse(task);
      calls.join.push({ task: parsed, outcome: JSON.parse(outcome) });
      if (controls.taskJoin !== null) return controls.taskJoin;
      liveTasks.delete(key(parsed));
      return outcome;
    },
    task_cancel: (request) => { calls.cancel.push(JSON.parse(request)); return controls.taskCancel; },
    scope_close: (scope) => {
      const parsed = JSON.parse(scope);
      calls.scopeClose.push(parsed);
      return closeOwner(parsed, controls.scopeClose);
    },
    runtime_close: (runtime) => {
      const parsed = JSON.parse(runtime);
      calls.runtimeClose.push(parsed);
      return closeOwner(parsed, controls.runtimeClose);
    },
    fetch_request: (request) => {
      calls.rawFetch.push(JSON.parse(request));
      return JSON.stringify({ outcome: "ok", value: {
        kind: "handle", value: JSON.parse(handle("fetch_request", nextFetch++)),
      } });
    },
  };
  const bindings = new SyntheticModule(names, function () {
    for (const name of names) {
      this.setExport(name, implementations[name] ?? (() => {
        throw new Error("Unexpected WASM ABI call: " + name);
      }));
    }
  }, { context });
  const modules = {
    sdk: new SourceTextModule(javaScript.sdk, { context, identifier: sdkPath }),
    fetch: new SourceTextModule(javaScript.fetch, { context, identifier: fetchPath }),
    core: new SourceTextModule(sources.core, { context, identifier: corePath }),
    streams: new SourceTextModule(sources.streams, { context, identifier: managerPath }),
  };
  await modules.sdk.link((specifier) => {
    if (specifier === "@asupersync/browser-core") return modules.core;
    if (specifier === "./fetch.js") return modules.fetch;
    if (specifier === "@asupersync/browser-core/webtransport-streams"
      || specifier === "./webtransport-streams.js") return modules.streams;
    assert.equal(specifier, "./asupersync.js", "only the generated WASM ABI is replaced");
    return bindings;
  });
  await modules.sdk.evaluate();
  const sdk = modules.sdk.namespace;
  const runtime = unwrap(await sdk.createBrowserRuntime({ fetchAuthority: authority }));
  const scope = unwrap(runtime.enterScope("fetch-stream-regression"));
  t.after(async () => {
    controls.taskCancel = unitJson;
    controls.taskJoin = null;
    for (const request of calls.network) {
      if (!request.response) request.headers.reject(new DOMException("fixture teardown", "AbortError"));
    }
    await Promise.all(handles.map((entry) => entry.cancel("fixture teardown")));
    controls.scopeClose = null;
    controls.runtimeClose = null;
    runtime.close();
    await turn();
  });
  function start(request = {}, owner = scope) {
    const result = unwrap(owner.fetch({ url: requestUrl, ...request }));
    handles.push(result);
    return result;
  }
  return { sdk, runtime, scope, calls, controls, authority, liveTasks, start };
}

test("SDK-FETCH-HEADERS: one admitted request returns headers before caller-driven body reads", { timeout: 5000 }, async (t) => {
  const { start, scope, calls, liveTasks } = await fixture(t);
  const handle = start({ headers: { "x-request": "headers-first" } });
  await turn();
  assert.equal(calls.network.length, 1);
  assert.equal(calls.spawn.length, 1);
  handleMatches(calls.spawn[0].scope, scope);
  assert.equal(calls.rawFetch.length, 0, "the raw fetch ABI would itself issue another browser request");
  const request = calls.network[0];
  assert.equal(request.init.redirect, "error");
  assert.equal(request.init.credentials, "omit");
  const body = request.respond(responseBody(), {
    status: 206, statusText: "Partial Content", headers: { "x-result": "headers-first" },
  });
  const metadata = unwrap(await handle.response());
  assert.equal(metadata.status, 206);
  assert.equal(metadata.statusText, "Partial Content");
  assert.equal(metadata.url, requestUrl);
  assert.ok(metadata.headers.some(([name, value]) => name === "x-result" && value === "headers-first"));
  assert.equal(body.events.length, 0, "publishing headers must not pull body bytes");
  assert.equal(calls.join.length, 0, "the task owns the unread body after headers");
  assert.equal(liveTasks.size, 1);
  const firstRead = handle.read();
  await turn();
  assert.deepEqual(body.events, [["pull"]]);
  failure(await handle.read(), "compatibility_rejected");
  body.input.enqueue(new Uint8Array([1, 2]));
  assert.deepEqual(bytes(await firstRead), [1, 2]);
  await turn();
  assert.equal(body.events.length, 1, "no read-ahead occurs after delivering a chunk");
  const secondRead = handle.read();
  await turn();
  assert.equal(body.events.filter(([event]) => event === "pull").length, 2);
  body.input.enqueue(new Uint8Array([3]));
  assert.deepEqual(bytes(await secondRead), [3]);
  body.input.close();
  assert.equal(unwrap(await handle.read()).done, true);
  unwrap(await handle.closed);
  assert.equal(body.readable.locked, false);
  assert.equal(calls.join.length, 1);
  assert.equal(calls.join[0].outcome.outcome, "ok");
  assert.equal(liveTasks.size, 0);
  assert.equal(unwrap(await handle.read()).done, true);
  assert.equal(calls.join.length, 1);
});

test("SDK-FETCH-AUTHORITY: grants reject origin, method, credentials and excess headers before effects", { timeout: 5000 }, async (t) => {
  const { scope, calls, authority } = await fixture(t);
  authority.allowedOrigins.push("https://forbidden.example.test");
  authority.allowedMethods.push("DELETE");
  authority.allowCredentials = true;
  authority.maxHeaderCount = 100;
  for (const request of [
    { url: "https://forbidden.example.test/data" },
    { url: requestUrl, method: "DELETE" },
    { url: requestUrl, credentials: true },
    { url: requestUrl, headers: [["x-one", "1"], ["x-two", "2"], ["x-three", "3"]] },
  ]) failure(scope.fetch(request), "capability_denied");
  assert.equal(calls.network.length, 0);
  assert.equal(calls.spawn.length, 0);
  assert.equal(calls.rawFetch.length, 0);
});

test("SDK-FETCH-LINEAGE: nested scopes inherit private grants and forged wrappers cannot acquire them", { timeout: 5000 }, async (t) => {
  const { sdk, runtime, scope, calls, start } = await fixture(t);
  const child = unwrap(scope.enterScope("child"));
  const grandchild = unwrap(child.enterScope("grandchild"));
  const forged = new sdk.RegionHandle(new sdk.CoreRegionHandle({
    ...grandchild.toJSON(), owner_token: "987",
  }), null, runtime);
  const invented = new sdk.RegionHandle(new sdk.CoreRegionHandle({
    ...grandchild.toJSON(), slot: 987,
  }), null, runtime);
  failure(forged.fetch({ url: requestUrl }), "capability_denied");
  failure(invented.fetch({ url: requestUrl }), "capability_denied");
  assert.equal(calls.spawn.length, 0);
  assert.equal(calls.network.length, 0);
  const handle = start({}, grandchild);
  await turn();
  calls.network[0].respond(null, { status: 204, statusText: "No Content" });
  assert.equal(unwrap(await handle.response()).status, 204);
  assert.equal(unwrap(await handle.read()).done, true);
  unwrap(await handle.closed);
  handleMatches(calls.spawn[0].scope, grandchild);
});

test("SDK-FETCH-BODY-LIMIT: cumulative response bounds cancel before publishing excess bytes", { timeout: 5000 }, async (t) => {
  const { start, calls } = await fixture(t);
  const handle = start({ maxResponseBytes: 3 });
  await turn();
  const body = calls.network[0].respond();
  unwrap(await handle.response());
  const first = handle.read();
  body.input.enqueue(new Uint8Array([1, 2]));
  assert.deepEqual(bytes(await first), [1, 2]);
  const excess = handle.read();
  body.input.enqueue(new Uint8Array([3, 4]));
  failure(await excess);
  failure(await handle.closed);
  assert.equal(body.events.filter(([event]) => event === "cancel").length, 1);
  assert.equal(body.readable.locked, false);
  assert.equal(calls.join.length, 1);
  assert.equal(calls.join[0].outcome.outcome, "err");
});

test("SDK-FETCH-READ-ERROR: a body error after headers retains its failure and releases the reader", { timeout: 5000 }, async (t) => {
  const { start, calls } = await fixture(t);
  const handle = start();
  await turn();
  const body = calls.network[0].respond();
  unwrap(await handle.response());
  const first = handle.read();
  await turn();
  body.input.enqueue(new Uint8Array([8]));
  assert.deepEqual(bytes(await first), [8]);
  const pending = handle.read();
  await turn();
  assert.equal(body.events.filter(([event]) => event === "pull").length, 2);
  body.input.error(new Error("network body interrupted"));
  const readFailure = failure(await pending, "internal_failure");
  assert.match(readFailure.message, /network body interrupted/);
  assert.deepEqual(clone(failure(await handle.closed)), clone(readFailure));
  assert.equal(body.readable.locked, false);
  assert.equal(calls.join.length, 1);
});

test("SDK-FETCH-CANCEL-HEADERS: cancellation aborts pending fetch and settles one terminal task", { timeout: 5000 }, async (t) => {
  const { start, calls } = await fixture(t);
  const handle = start();
  const headers = handle.response();
  await turn();
  assert.equal(calls.network.length, 1);
  assert.equal(calls.network[0].init.signal.aborted, false);
  const terminal = cancellation(await handle.cancel("navigation left"));
  assert.equal(terminal.message, "navigation left");
  assert.deepEqual(clone(cancellation(await headers)), clone(terminal));
  assert.deepEqual(clone(cancellation(await handle.closed)), clone(terminal));
  assert.equal(calls.network[0].init.signal.aborted, true);
  assert.equal(calls.network[0].events.filter(([event]) => event === "abort").length, 1);
  assert.equal(calls.join.length, 1);
});

test("SDK-FETCH-CANCEL-DRAIN: pending read cancellation waits for native body cleanup", { timeout: 5000 }, async (t) => {
  const cleanup = deferred();
  const { start, calls } = await fixture(t);
  const handle = start();
  await turn();
  const body = calls.network[0].respond(responseBody({ cancel: () => cleanup.promise }));
  unwrap(await handle.response());
  const pending = handle.read();
  await turn();
  assert.deepEqual(body.events, [["pull"]]);
  let completed = false;
  const cancelling = handle.cancel("stop reading").then((result) => { completed = true; return result; });
  await turn();
  assert.equal(completed, false);
  assert.equal(body.readable.locked, true, "the reader remains owned while cleanup runs");
  assert.equal(body.events.filter(([event]) => event === "cancel").length, 1);
  cleanup.resolve();
  const terminal = cancellation(await cancelling);
  assert.deepEqual(clone(cancellation(await pending)), clone(terminal));
  assert.deepEqual(clone(cancellation(await handle.closed)), clone(terminal));
  assert.equal(body.readable.locked, false);
  assert.equal(calls.join.length, 1);
});

test("SDK-FETCH-LATE-RESPONSE: cancellation drains a response delivered after abort", { timeout: 5000 }, async (t) => {
  const { start, calls } = await fixture(t, { ignoreAbort: true });
  const handle = start();
  const headers = handle.response();
  await turn();
  const cancelled = handle.cancel("late host response");
  assert.equal(calls.network[0].init.signal.aborted, true);
  let closed = false;
  const completion = handle.closed.then((result) => { closed = true; return result; });
  await turn();
  assert.equal(closed, false, "a late host response still has to be disposed");
  const body = calls.network[0].respond();
  const terminal = cancellation(await completion);
  assert.deepEqual(clone(cancellation(await cancelled)), clone(terminal));
  assert.deepEqual(clone(cancellation(await headers)), clone(terminal));
  assert.equal(body.events.filter(([event]) => event === "cancel").length, 1);
  assert.equal(body.readable.locked, false);
});

test("SDK-FETCH-OWNERSHIP: an injected live-task close refusal preserves responses until explicit cancellation", { timeout: 5000 }, async (t) => {
  const { runtime, scope, start, calls, liveTasks } = await fixture(t);
  const child = unwrap(scope.enterScope("child"));
  const grandchild = unwrap(child.enterScope("grandchild"));
  const sibling = unwrap(runtime.enterScope("sibling"));
  const handles = [start({}, scope), start({}, child), start({}, grandchild), start({}, sibling)];
  await turn();
  const bodies = calls.network.map((request) => request.respond());
  await Promise.all(handles.map(async (handle) => unwrap(await handle.response())));
  const pending = handles.map((handle) => handle.read());
  await turn();
  assert.ok(bodies.every((body) => body.readable.locked));
  assert.equal(liveTasks.size, 4);
  failure(child.close(), "compatibility_rejected");
  assert.ok(calls.network.every((request) => !request.init.signal.aborted));
  for (const index of [1, 2]) {
    cancellation(await handles[index].cancel("child ending"));
    cancellation(await pending[index]);
    assert.equal(bodies[index].readable.locked, false);
  }
  unwrap(child.close());
  failure(child.fetch({ url: requestUrl }), "capability_denied");
  for (const index of [0, 3]) {
    assert.equal(calls.network[index].init.signal.aborted, false);
    bodies[index].input.enqueue(new Uint8Array([index, 9]));
    assert.deepEqual(bytes(await pending[index]), [index, 9]);
    pending[index] = handles[index].read();
  }
  failure(runtime.close(), "compatibility_rejected");
  for (const index of [0, 3]) {
    cancellation(await handles[index].cancel("runtime ending"));
    cancellation(await pending[index]);
    assert.equal(bodies[index].readable.locked, false);
  }
  unwrap(runtime.close());
  assert.equal(liveTasks.size, 0);
  assert.equal(calls.network.length, 4);
  assert.equal(calls.spawn.length, 4);
  assert.equal(calls.rawFetch.length, 0);
});

test("SDK-FETCH-CLOSE-DENIED: failed owner close preserves grants and existing body reads", { timeout: 5000 }, async (t) => {
  const { start, scope, runtime, calls, controls } = await fixture(t);
  const rejected = JSON.stringify({ outcome: "err", failure: {
    code: "capability_denied", recoverability: "permanent", message: "owner close denied",
  } });
  const handle = start();
  await turn();
  const body = calls.network[0].respond();
  unwrap(await handle.response());
  controls.scopeClose = rejected;
  controls.runtimeClose = rejected;
  failure(scope.close(), "capability_denied");
  failure(runtime.close(), "capability_denied");
  assert.equal(calls.network[0].init.signal.aborted, false);
  const reading = handle.read();
  body.input.enqueue(new Uint8Array([10]));
  assert.deepEqual(bytes(await reading), [10]);
  body.input.close();
  assert.equal(unwrap(await handle.read()).done, true);
  unwrap(await handle.closed);
  const subsequent = start();
  await turn();
  assert.equal(calls.network.length, 2);
  calls.network[1].respond(null, { status: 204, statusText: "No Content" });
  unwrap(await subsequent.response());
  assert.equal(unwrap(await subsequent.read()).done, true);
  unwrap(await subsequent.closed);
});

test("SDK-FETCH-REDIRECT: extra caller options cannot enable automatic redirects", { timeout: 5000 }, async (t) => {
  const { start, calls } = await fixture(t);
  const handle = start({ redirect: "follow" });
  await turn();
  assert.equal(calls.network[0].init.redirect, "error");
  assert.equal(calls.network[0].init.credentials, "omit");
  calls.network[0].headers.reject(new TypeError("redirect disallowed by host fetch"));
  assert.match(failure(await handle.response(), "internal_failure").message, /redirect/);
  failure(await handle.closed);
  assert.equal(calls.network.length, 1);
  assert.equal(calls.join.length, 1);
});

test("SDK-FETCH-HTTP-ERROR: HTTP failure status remains a readable response", { timeout: 5000 }, async (t) => {
  const { start, calls } = await fixture(t);
  const handle = start();
  await turn();
  const body = calls.network[0].respond(responseBody(), { status: 404, statusText: "Not Found" });
  assert.equal(unwrap(await handle.response()).status, 404);
  const reading = handle.read();
  body.input.enqueue(new TextEncoder().encode("missing"));
  body.input.close();
  assert.equal(new TextDecoder().decode(unwrap(await reading).value), "missing");
  assert.equal(unwrap(await handle.read()).done, true);
  unwrap(await handle.closed);
});

test("SDK-FETCH-RAW-COMPAT: legacy fetchRequest retains its raw ABI path and return kind", { timeout: 5000 }, async (t) => {
  const { sdk, scope, calls } = await fixture(t);
  const handle = unwrap(scope.fetchRequest({ url: requestUrl, method: "POST", body: new Uint8Array([1, 2]) }));
  assert.ok(handle instanceof sdk.FetchHandle);
  assert.equal(handle.toJSON().kind, "fetch_request");
  assert.equal(calls.rawFetch.length, 1);
  assert.equal(calls.rawFetch[0].url, requestUrl);
  assert.deepEqual(calls.rawFetch[0].body, [1, 2]);
  handleMatches(calls.rawFetch[0].scope, scope);
  assert.equal(calls.network.length, 0);
  assert.equal(calls.spawn.length, 0);
});

test("SDK-FETCH-DEFAULT-DENY: an empty runtime grant has no implicit fetch authority", { timeout: 5000 }, async (t) => {
  const { scope, calls } = await fixture(t, { authority: {} });
  failure(scope.fetch({ url: requestUrl }), "capability_denied");
  assert.equal(calls.network.length, 0);
  assert.equal(calls.spawn.length, 0);
});

test("SDK-FETCH-CANCEL-DENIED: ABI refusal leaves a pending body read and its network request intact", { timeout: 5000 }, async (t) => {
  const { start, calls, controls } = await fixture(t);
  const handle = start();
  await turn();
  const body = calls.network[0].respond();
  unwrap(await handle.response());
  const pending = handle.read();
  await turn();
  controls.taskCancel = JSON.stringify({ outcome: "err", failure: {
    code: "capability_denied", recoverability: "permanent", message: "cancel denied",
  } });
  failure(await handle.cancel("denied request"), "capability_denied");
  assert.equal(calls.network[0].init.signal.aborted, false);
  assert.equal(body.events.filter(([event]) => event === "cancel").length, 0);
  body.input.enqueue(new Uint8Array([20]));
  assert.deepEqual(bytes(await pending), [20]);
  body.input.close();
  assert.equal(unwrap(await handle.read()).done, true);
  unwrap(await handle.closed);
  assert.equal(calls.join.length, 1);
});

test("SDK-FETCH-REQUEST-BYTES: admitted request bodies are copied and oversized bodies have no effect", { timeout: 5000 }, async (t) => {
  const { sdk, scope, start, calls } = await fixture(t);
  failure(scope.fetch({ url: requestUrl, method: "POST",
    body: new Uint8Array(sdk.BROWSER_FETCH_LIMITS.maxRequestBytes + 1) }));
  assert.equal(calls.network.length, 0);
  assert.equal(calls.spawn.length, 0);
  const input = new Uint8Array([21, 22, 23]);
  const handle = start({ method: "POST", body: new DataView(input.buffer, 1, 2) });
  input.fill(99);
  await turn();
  assert.deepEqual(Array.from(calls.network[0].init.body), [22, 23]);
  calls.network[0].respond(null, { status: 204, statusText: "No Content" });
  unwrap(await handle.response());
  unwrap(await handle.closed);
});

test("SDK-FETCH-IDLE-ERROR: idle reader failure ends its task while clean reader closure still requires EOF consumption", { timeout: 5000 }, async (t) => {
  const { start, calls, liveTasks } = await fixture(t);
  const failed = start();
  await turn();
  const failedBody = calls.network[0].respond();
  unwrap(await failed.response());
  assert.deepEqual(failedBody.events, []);
  failedBody.input.error(new Error("idle network disconnect"));
  assert.match(failure(await failed.closed, "internal_failure").message, /idle network disconnect/);
  assert.equal(failedBody.readable.locked, false);
  assert.equal(liveTasks.size, 0);
  const clean = start();
  await turn();
  const cleanBody = calls.network[1].respond();
  unwrap(await clean.response());
  cleanBody.input.close();
  await turn();
  assert.equal(liveTasks.size, 1, "host closure alone is not application consumption of EOF");
  assert.equal(calls.join.length, 1);
  assert.equal(unwrap(await clean.read()).done, true);
  unwrap(await clean.closed);
  assert.equal(liveTasks.size, 0);
});

test("SDK-FETCH-CAPACITY: one runtime budget covers sibling scopes and remains reserved during late-host cleanup", { timeout: 5000 }, async (t) => {
  const { sdk, scope, start, calls, liveTasks } = await fixture(t, { ignoreAbort: true });
  const child = unwrap(scope.enterScope("shares-budget"));
  const admitted = [];
  for (let index = 0; index < sdk.BROWSER_FETCH_LIMITS.maxRequestsPerRuntime; index += 1) {
    admitted.push(start({}, index % 2 ? child : scope));
  }
  await turn();
  assert.equal(calls.network.length, 64);
  failure(child.fetch({ url: requestUrl }), "compatibility_rejected");
  const cancelling = admitted[0].cancel("free a slot after cleanup");
  await turn();
  assert.equal(calls.network[0].init.signal.aborted, true);
  failure(scope.fetch({ url: requestUrl }), "compatibility_rejected");
  assert.equal(calls.network.length, 64);
  assert.equal(liveTasks.size, 64);
  const late = calls.network[0].respond();
  cancellation(await cancelling);
  assert.equal(late.readable.locked, false);
  assert.equal(liveTasks.size, 63);
  const replacement = start();
  await turn();
  assert.equal(calls.network.length, 65);
  calls.network[64].respond(null, { status: 204, statusText: "No Content" });
  unwrap(await replacement.response());
  unwrap(await replacement.closed);
});

test("SDK-FETCH-ADMISSION-REENTRY: ABI version getters cannot overbook the final runtime request slot", { timeout: 5000 }, async (t) => {
  const { sdk, scope, start, calls } = await fixture(t);
  for (let index = 0; index < sdk.BROWSER_FETCH_LIMITS.maxRequestsPerRuntime - 1; index += 1) start();
  let nested;
  let visited = 0;
  const version = {
    get major() {
      visited += 1;
      if (nested === undefined) nested = scope.fetch({ url: requestUrl });
      return 1;
    },
    minor: 0,
  };
  const outer = scope.fetch({ url: requestUrl }, version);
  await turn();
  assert.ok(visited > 0, "the hostile caller getter was actually invoked");
  assert.equal([nested, outer].filter((entry) => entry.outcome === "ok").length, 1);
  failure([nested, outer].find((entry) => entry.outcome !== "ok"), "compatibility_rejected");
  assert.equal(calls.network.length, 64);
  assert.equal(calls.spawn.length, 64);
  const winner = unwrap([nested, outer].find((entry) => entry.outcome === "ok"));
  cancellation(await winner.cancel("reentry check complete"));
});

test("SDK-FETCH-EOF-REENTRY: cancellation from native reader release wins over EOF and awaits cleanup", { timeout: 5000 }, async (t) => {
  const cleanup = deferred();
  const { start, calls } = await fixture(t);
  const handle = start();
  await turn();
  const body = responseBody();
  const acquire = body.readable.getReader.bind(body.readable);
  let cancelling;
  let cancelStarted = false;
  body.readable.getReader = () => {
    const reader = acquire();
    const release = reader.releaseLock.bind(reader);
    const cancel = reader.cancel.bind(reader);
    reader.cancel = async (reason) => {
      cancelStarted = true;
      await cancel(reason);
      await cleanup.promise;
    };
    reader.releaseLock = () => {
      if (cancelling === undefined) cancelling = handle.cancel("cancel during EOF release");
      return release();
    };
    return reader;
  };
  calls.network[0].respond(body);
  unwrap(await handle.response());
  body.input.close();
  const eof = handle.read();
  let completed = false;
  const terminal = handle.closed.then((outcome) => { completed = true; return outcome; });
  await turn();
  assert.equal(cancelStarted, true);
  assert.equal(completed, false, "EOF must not publish success before reentrant cancellation drains");
  assert.equal(calls.join.length, 0);
  cleanup.resolve();
  cancellation(await eof);
  cancellation(await cancelling);
  cancellation(await terminal);
  assert.equal(calls.join.length, 1);
  assert.equal(calls.join[0].outcome.outcome, "cancelled");
});

test("SDK-FETCH-JOIN-DENIED: refused EOF publication is an error and keeps its runtime admission reserved", { timeout: 5000 }, async (t) => {
  const { sdk, scope, start, calls, controls, liveTasks } = await fixture(t);
  const handle = start();
  await turn();
  const body = calls.network[0].respond();
  unwrap(await handle.response());
  const rejected = { outcome: "err", failure: {
    code: "invalid_handle", recoverability: "permanent", message: "terminal publication refused",
  } };
  controls.taskJoin = JSON.stringify(rejected);
  body.input.close();
  assert.deepEqual(clone(await handle.read()), rejected);
  assert.deepEqual(clone(await handle.closed), rejected);
  assert.equal(body.readable.locked, false);
  assert.equal(liveTasks.size, 1, "the ABI did not acknowledge retirement of this task");
  assert.deepEqual(clone(await handle.read()), rejected);
  controls.taskJoin = null;
  for (let index = 0; index < sdk.BROWSER_FETCH_LIMITS.maxRequestsPerRuntime - 1; index += 1) start();
  failure(scope.fetch({ url: requestUrl }), "compatibility_rejected");
  assert.equal(calls.network.length, 64, "a refused terminal cannot recycle its runtime admission");
});

test("SDK-FETCH-EMPTY-JOIN-DENIED: a read awaiting headers receives publication failure for a bodyless response", { timeout: 5000 }, async (t) => {
  const { start, calls, controls, liveTasks } = await fixture(t);
  const handle = start();
  const reading = handle.read();
  await turn();
  const rejected = { outcome: "err", failure: {
    code: "invalid_handle", recoverability: "permanent", message: "empty response publication refused",
  } };
  controls.taskJoin = JSON.stringify(rejected);
  calls.network[0].respond(null, { status: 204, statusText: "No Content" });
  assert.equal(unwrap(await handle.response()).status, 204);
  assert.deepEqual(clone(await reading), rejected);
  assert.deepEqual(clone(await handle.closed), rejected);
  assert.equal(liveTasks.size, 1);
});

test("SDK-FETCH-CANCEL-JOIN-DENIED: a mismatched cancellation receipt preserves admission and exposes the refusal", { timeout: 5000 }, async (t) => {
  const { sdk, scope, start, calls, controls, liveTasks } = await fixture(t);
  const handle = start();
  await turn();
  const rejected = { outcome: "err", failure: {
    code: "invalid_handle", recoverability: "permanent", message: "cancellation publication refused",
  } };
  controls.taskJoin = JSON.stringify(rejected);
  assert.deepEqual(clone(await handle.cancel("legitimate cancellation")), rejected);
  assert.deepEqual(clone(await handle.closed), rejected);
  assert.equal(calls.join[0].outcome.outcome, "cancelled", "the refused publication was a non-ok task outcome");
  assert.equal(calls.network[0].init.signal.aborted, true);
  assert.equal(liveTasks.size, 1);
  controls.taskJoin = null;
  for (let index = 0; index < sdk.BROWSER_FETCH_LIMITS.maxRequestsPerRuntime - 1; index += 1) start();
  failure(scope.fetch({ url: requestUrl }), "compatibility_rejected");
  assert.equal(calls.network.length, 64);
});

test("SDK-FETCH-LOCAL-HTTP: actual fetch streams a gated response and refuses to follow redirects", { timeout: 5000 }, async (t) => {
  const first = deferred();
  const tail = deferred();
  const requests = [];
  let redirectedDestinationHits = 0;
  const server = createServer((request, response) => {
    requests.push(request.url);
    if (request.url === "/stream") {
      response.writeHead(200, { "content-type": "application/octet-stream", "x-proof": "real-http" });
      response.flushHeaders();
      void (async () => {
        await first.promise;
        response.write(new Uint8Array([61, 62]));
        await tail.promise;
        response.end(new Uint8Array([63]));
      })().catch((error) => response.destroy(error));
    } else if (request.url === "/redirect") {
      response.writeHead(302, { location: "/destination" });
      response.end();
    } else {
      redirectedDestinationHits += 1;
      response.end("must not be contacted");
    }
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(async () => {
    first.resolve();
    tail.resolve();
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  const origin = "http://127.0.0.1:" + server.address().port;
  const { start, calls, liveTasks } = await fixture(t, {
    actualFetch: fetch,
    authority: { allowedOrigins: [origin], allowedMethods: ["GET"], allowCredentials: false, maxHeaderCount: 0 },
  });
  const operation = start({ url: origin + "/stream" });
  const metadata = unwrap(await operation.response());
  assert.equal(metadata.status, 200);
  assert.ok(metadata.headers.some(([name, value]) => name === "x-proof" && value === "real-http"));
  assert.deepEqual(requests, ["/stream"]);
  assert.equal(calls.spawn.length, 1);
  assert.equal(calls.rawFetch.length, 0);
  assert.equal(liveTasks.size, 1);
  let firstReadSettled = false;
  const reading = operation.read().then((outcome) => { firstReadSettled = true; return outcome; });
  await turn();
  assert.equal(firstReadSettled, false, "real HTTP headers arrived before the server allowed body bytes");
  first.resolve();
  const received = bytes(await reading);
  while (received.length < 2) received.push(...bytes(await operation.read()));
  assert.deepEqual(received, [61, 62]);
  let closed = false;
  const completion = operation.closed.then((outcome) => { closed = true; return outcome; });
  await turn();
  assert.equal(closed, false, "the live response tail still belongs to its admitted task");
  tail.resolve();
  while (true) {
    const chunk = unwrap(await operation.read());
    if (chunk.done) break;
    received.push(...chunk.value);
  }
  assert.deepEqual(received, [61, 62, 63]);
  unwrap(await completion);
  assert.equal(liveTasks.size, 0);
  assert.equal(calls.join.length, 1);
  const redirected = start({ url: origin + "/redirect", redirect: "follow" });
  failure(await redirected.response(), "internal_failure");
  failure(await redirected.closed);
  assert.deepEqual(requests, ["/stream", "/redirect"]);
  assert.equal(redirectedDestinationHits, 0);
  assert.equal(calls.network.length, 2);
  assert.equal(calls.join.length, 2);
  assert.equal(liveTasks.size, 0);
});

for (const parentKind of ["runtime", "scope"]) {
  test("SDK-FETCH-PARENT-SNAPSHOT-" + parentKind + ": ABI serialization cannot reparent a new scope's authority", { timeout: 5000 }, async (t) => {
    const { sdk, runtime, scope, start, calls } = await fixture(t);
    const permissive = unwrap(await sdk.createBrowserRuntime({ fetchAuthority: {
      allowedOrigins: ["https://forbidden.example.test"], allowedMethods: ["GET"],
      maxHeaderCount: 0, allowCredentials: false,
    } }));
    const foreignScope = unwrap(permissive.enterScope("different-authority"));
    t.after(() => permissive.close());
    const parent = parentKind === "runtime" ? runtime : scope;
    const replacement = parentKind === "runtime" ? permissive : foreignScope;
    const originalCore = parent.core;
    let serialized = false;
    const version = { major: 1, minor: 0, toJSON() {
      serialized = true;
      parent.core = replacement.core;
      return { major: 1, minor: 0 };
    } };
    const entered = parent.enterScope("retain-original-parent", version);
    parent.core = originalCore;
    const child = unwrap(entered);
    assert.equal(serialized, true, "the hostile serializer ran after parent capture");
    handleMatches(calls.scopeEnter.at(-1).parent, { toJSON: () => originalCore.toJSON() });
    failure(child.fetch({ url: "https://forbidden.example.test/data" }), "capability_denied");
    assert.equal(calls.network.length, 0);
    const allowed = start({}, child);
    await turn();
    calls.network[0].respond(null, { status: 204, statusText: "No Content" });
    unwrap(await allowed.response());
    unwrap(await allowed.closed);
  });

  test("SDK-FETCH-CLOSE-SNAPSHOT-" + parentKind + ": ABI serialization cannot close another owner's fetch", { timeout: 5000 }, async (t) => {
    const { sdk, runtime, scope, start, calls, liveTasks } = await fixture(t);
    const foreignRuntime = unwrap(await sdk.createBrowserRuntime({ fetchAuthority: {
      allowedOrigins: ["https://api.example.test"], allowedMethods: ["GET"],
      maxHeaderCount: 0, allowCredentials: false,
    } }));
    const foreignScope = unwrap(foreignRuntime.enterScope("surviving-owner"));
    t.after(() => foreignRuntime.close());
    const operation = start({}, foreignScope);
    await turn();
    const body = calls.network[0].respond();
    unwrap(await operation.response());
    const owner = parentKind === "runtime" ? runtime : scope;
    const replacement = parentKind === "runtime" ? foreignRuntime : foreignScope;
    const originalCore = owner.core;
    let serialized = false;
    const version = { major: 1, minor: 0, toJSON() {
      serialized = true;
      owner.core = replacement.core;
      return { major: 1, minor: 0 };
    } };
    const closed = owner.close(version);
    owner.core = originalCore;
    unwrap(closed);
    assert.equal(serialized, true);
    const recorded = parentKind === "runtime" ? calls.runtimeClose.at(-1) : calls.scopeClose.at(-1);
    handleMatches(recorded, { toJSON: () => originalCore.toJSON() });
    assert.equal(calls.network[0].init.signal.aborted, false);
    assert.equal(liveTasks.size, 1);
    const reading = operation.read();
    body.input.enqueue(new Uint8Array([70]));
    assert.deepEqual(bytes(await reading), [70]);
    body.input.close();
    assert.equal(unwrap(await operation.read()).done, true);
    unwrap(await operation.closed);
    assert.equal(liveTasks.size, 0);
  });
}

test("SDK-FETCH-CLOSE-ASYNC: scope closure drains host cleanup before ABI close and fences new descendants", { timeout: 5000 }, async (t) => {
  const cleanup = deferred();
  const { runtime, scope, start, calls, liveTasks } = await fixture(t);
  const child = unwrap(scope.enterScope("draining-child"));
  const sibling = unwrap(runtime.enterScope("surviving-sibling"));
  const draining = start({}, child);
  const survivor = start({}, sibling);
  await turn();
  const body = calls.network[0].respond(responseBody({ cancel: () => cleanup.promise }));
  const survivingBody = calls.network[1].respond();
  unwrap(await draining.response());
  unwrap(await survivor.response());
  const pending = draining.read();
  await turn();
  assert.deepEqual(body.events, [["pull"]]);
  const firstClose = child.closeAsync();
  const sameClose = child.closeAsync();
  let completed = false;
  const completion = firstClose.then((outcome) => { completed = true; return outcome; });
  failure(child.fetch({ url: requestUrl }), "capability_denied");
  const lateChild = unwrap(child.enterScope("created-during-drain"));
  failure(lateChild.fetch({ url: requestUrl }), "capability_denied");
  await turn();
  assert.equal(completed, false);
  assert.equal(calls.scopeClose.length, 0, "host drain must finish before submitting owner close to the ABI");
  assert.equal(calls.cancel.length, 1);
  assert.equal(calls.cancel[0].kind, "scope_close");
  assert.equal(liveTasks.size, 2);
  assert.equal(body.readable.locked, true);
  assert.equal(calls.network[1].init.signal.aborted, false);
  const survivorRead = survivor.read();
  survivingBody.input.enqueue(new Uint8Array([80]));
  assert.deepEqual(bytes(await survivorRead), [80]);
  cleanup.resolve();
  unwrap(await completion);
  unwrap(await sameClose);
  assert.equal(cancellation(await pending).kind, "scope_close");
  cancellation(await draining.closed);
  assert.equal(body.readable.locked, false);
  assert.equal(calls.scopeClose.length, 1);
  handleMatches(calls.scopeClose[0], child);
  assert.equal(liveTasks.size, 1);
  failure(lateChild.fetch({ url: requestUrl }), "capability_denied");
  survivingBody.input.close();
  assert.equal(unwrap(await survivor.read()).done, true);
  unwrap(await survivor.closed);
});

test("SDK-FETCH-CLOSE-ASYNC-LATE: runtime closure waits for a late response and owns the entire nested fetch tree", { timeout: 5000 }, async (t) => {
  const { runtime, scope, start, calls, liveTasks } = await fixture(t, { ignoreAbort: true });
  const child = unwrap(scope.enterScope("child"));
  const grandchild = unwrap(child.enterScope("grandchild"));
  const first = start({}, scope);
  const second = start({}, grandchild);
  await turn();
  const liveBody = calls.network[0].respond();
  unwrap(await first.response());
  const pending = first.read();
  const lateHead = second.response();
  await turn();
  const closing = runtime.closeAsync();
  failure(grandchild.fetch({ url: requestUrl }), "capability_denied");
  const newlyEntered = unwrap(runtime.enterScope("entered-during-close"));
  failure(newlyEntered.fetch({ url: requestUrl }), "capability_denied");
  await turn();
  assert.ok(calls.network.every((request) => request.init.signal.aborted));
  assert.equal(calls.runtimeClose.length, 0);
  assert.equal(cancellation(await pending).kind, "runtime_close");
  const lateBody = calls.network[1].respond();
  unwrap(await closing);
  assert.equal(cancellation(await lateHead).kind, "runtime_close");
  cancellation(await first.closed);
  cancellation(await second.closed);
  assert.equal(liveBody.readable.locked, false);
  assert.equal(lateBody.readable.locked, false);
  assert.equal(lateBody.events.filter(([event]) => event === "cancel").length, 1);
  assert.equal(calls.runtimeClose.length, 1);
  assert.equal(liveTasks.size, 0);
});

test("SDK-FETCH-CLOSE-ASYNC-CANCEL-DENIED: cancellation refusal preserves the fetch and permits a later close attempt", { timeout: 5000 }, async (t) => {
  const { scope, start, calls, controls, liveTasks } = await fixture(t);
  const operation = start();
  await turn();
  const body = calls.network[0].respond();
  unwrap(await operation.response());
  const rejected = { outcome: "err", failure: {
    code: "capability_denied", recoverability: "permanent", message: "drain cancellation denied",
  } };
  controls.taskCancel = JSON.stringify(rejected);
  assert.deepEqual(clone(await scope.closeAsync()), rejected);
  assert.equal(calls.scopeClose.length, 0);
  assert.equal(calls.network[0].init.signal.aborted, false);
  const reading = operation.read();
  body.input.enqueue(new Uint8Array([81]));
  assert.deepEqual(bytes(await reading), [81]);
  const subsequent = start();
  await turn();
  assert.equal(calls.network.length, 2, "a failed attempt releases its admission fence");
  calls.network[1].respond(null, { status: 204, statusText: "No Content" });
  unwrap(await subsequent.response());
  unwrap(await subsequent.closed);
  controls.taskCancel = unitJson;
  unwrap(await scope.closeAsync());
  cancellation(await operation.closed);
  assert.equal(calls.scopeClose.length, 1);
  assert.equal(liveTasks.size, 0);
});

test("SDK-FETCH-CLOSE-ASYNC-ABI-DENIED: final owner refusal is returned after cleanup and can be retried", { timeout: 5000 }, async (t) => {
  const { runtime, start, calls, controls, liveTasks } = await fixture(t);
  const operation = start();
  await turn();
  const rejected = { outcome: "err", failure: {
    code: "compatibility_rejected", recoverability: "transient", message: "runtime close refused",
  } };
  controls.runtimeClose = JSON.stringify(rejected);
  assert.deepEqual(clone(await runtime.closeAsync()), rejected);
  cancellation(await operation.closed);
  assert.equal(liveTasks.size, 0);
  assert.equal(calls.runtimeClose.length, 1);
  const retryWork = start();
  await turn();
  controls.runtimeClose = null;
  unwrap(await runtime.closeAsync());
  cancellation(await retryWork.closed);
  assert.equal(calls.runtimeClose.length, 2);
  assert.equal(liveTasks.size, 0);
});

for (const kind of ["generic-task", "webtransport"]) {
  test("SDK-FETCH-CLOSE-ASYNC-UNRELATED-" + kind + ": unrelated work preserves an injected ABI close refusal", { timeout: 5000 }, async (t) => {
    const { sdk, scope, start, calls, liveTasks } = await fixture(t);
    const fetch = start();
    const other = kind === "generic-task"
      ? unwrap(scope.spawnTask({ label: "unrelated-task" }))
      : unwrap(scope.openWebTransport("https://transport.example.test/session"));
    await turn();
    assert.equal(liveTasks.size, 2);
    failure(await scope.closeAsync(), "compatibility_rejected");
    cancellation(await fetch.closed);
    assert.equal(liveTasks.size, 1);
    assert.equal(calls.cancel.length, 1);
    assert.equal(calls.cancel[0].task.slot, calls.issuedTasks[0].slot);
    if (kind === "webtransport") {
      assert.equal(calls.transports[0].closes, 0);
      assert.equal(calls.transports[0].datagrams.readable.locked, true);
      unwrap(await other.ready());
      cancellation(other.close());
      await turn();
    } else {
      unwrap(other.join(sdk.Outcome.ok(undefined)));
    }
    assert.equal(liveTasks.size, 0);
    unwrap(await scope.closeAsync());
    assert.equal(calls.scopeClose.length, 2);
  });
}

test("SDK-FETCH-CLOSE-ASYNC-PUBLICATION: refused task publication blocks owner close after host cleanup", { timeout: 5000 }, async (t) => {
  const { scope, start, calls, controls, liveTasks } = await fixture(t);
  const operation = start();
  await turn();
  const rejected = { outcome: "err", failure: {
    code: "invalid_handle", recoverability: "permanent", message: "drain terminal refused",
  } };
  controls.taskJoin = JSON.stringify(rejected);
  assert.deepEqual(clone(await scope.closeAsync()), rejected);
  assert.deepEqual(clone(await operation.closed), rejected);
  assert.equal(calls.network[0].init.signal.aborted, true);
  assert.equal(calls.scopeClose.length, 0);
  assert.equal(liveTasks.size, 1);
});

for (const route of ["task-handle", "cancellation-token"]) {
  test("SDK-FETCH-GENERIC-CANCEL-SNAPSHOT-" + route + ": host cancellation uses the exact task admitted by the ABI", { timeout: 5000 }, async (t) => {
    const { sdk, start, calls } = await fixture(t);
    const first = start();
    const survivor = start();
    await turn();
    const firstBody = calls.network[0].respond();
    const survivingBody = calls.network[1].respond();
    unwrap(await first.response());
    unwrap(await survivor.response());
    const firstRaw = calls.issuedTasks[0];
    let supplied = firstRaw;
    class ChangingTask extends sdk.CoreTaskHandle {
      toJSON() { return supplied; }
    }
    const task = new ChangingTask(firstRaw);
    let serialized = false;
    const version = { major: 1, minor: 0, toJSON() {
      serialized = true;
      supplied = calls.issuedTasks[1];
      return { major: 1, minor: 0 };
    } };
    const result = route === "task-handle"
      ? new sdk.TaskHandle(task).cancel("navigation", "cancel original task", version)
      : new sdk.CancellationToken("navigation", "cancel original task").cancel(task, version);
    unwrap(result);
    assert.equal(serialized, true);
    assert.equal(calls.cancel[0].task.slot, firstRaw.slot);
    assert.equal(cancellation(await first.closed).kind, "navigation");
    assert.equal(firstBody.readable.locked, false);
    assert.equal(calls.network[0].init.signal.aborted, true);
    assert.equal(calls.network[1].init.signal.aborted, false);
    const reading = survivor.read();
    survivingBody.input.enqueue(new Uint8Array([82]));
    assert.deepEqual(bytes(await reading), [82]);
    survivingBody.input.close();
    assert.equal(unwrap(await survivor.read()).done, true);
    unwrap(await survivor.closed);
  });
}

for (const poison of ["outcome-getter", "error-message-getter"]) {
  test("SDK-FETCH-HOST-REJECTION-" + poison + ": hostile thrown values cannot strand pending response ownership", { timeout: 5000 }, async (t) => {
    const { start, calls, liveTasks } = await fixture(t);
    const operation = start();
    await turn();
    let rejected;
    if (poison === "outcome-getter") {
      rejected = { get outcome() { throw new Error("hostile outcome access"); } };
    } else {
      rejected = new Error();
      Object.defineProperty(rejected, "message", { get() { throw new Error("hostile message access"); } });
    }
    calls.network[0].headers.reject(rejected);
    failure(await operation.response(), "internal_failure");
    failure(await operation.closed, "internal_failure");
    assert.equal(calls.join.length, 1);
    assert.equal(liveTasks.size, 0);
  });
}

test("SDK-FETCH-CANCEL-OUTCOME: caller mutation of a pending terminal cannot alter the later task publication", { timeout: 5000 }, async (t) => {
  const { start, calls } = await fixture(t, { ignoreAbort: true });
  const operation = start();
  await turn();
  const cancelling = operation.cancel("retain original cancellation");
  const early = await operation.response();
  const detail = cancellation(early);
  Reflect.set(early, "outcome", "ok");
  Reflect.set(early, "value", undefined);
  Reflect.set(detail, "kind", "forged_success");
  Reflect.set(detail, "message", "forged result");
  Reflect.deleteProperty(early, "cancellation");
  const body = calls.network[0].respond();
  const terminal = cancellation(await cancelling);
  assert.equal(terminal.kind, "fetch_cancel");
  assert.equal(terminal.message, "retain original cancellation");
  assert.equal(cancellation(await operation.closed).kind, "fetch_cancel");
  assert.equal(calls.join[0].outcome.outcome, "cancelled");
  assert.equal(calls.join[0].outcome.cancellation.kind, "fetch_cancel");
  assert.equal(body.readable.locked, false);
});

test("SDK-FETCH-HEAD-OUTCOME: caller mutation of shared response metadata cannot poison body reads", { timeout: 5000 }, async (t) => {
  const { start, calls } = await fixture(t);
  const operation = start();
  await turn();
  const body = calls.network[0].respond();
  const headers = await operation.response();
  const metadata = unwrap(headers);
  Reflect.set(headers, "outcome", "err");
  Reflect.set(headers, "failure", { code: "internal_failure", recoverability: "permanent", message: "forged failure" });
  Reflect.set(metadata, "status", 599);
  const reading = operation.read();
  body.input.enqueue(new Uint8Array([83]));
  assert.deepEqual(bytes(await reading), [83]);
  body.input.close();
  assert.equal(unwrap(await operation.read()).done, true);
  unwrap(await operation.closed);
  assert.equal(unwrap(await operation.response()).status, 200);
  assert.equal(calls.join[0].outcome.outcome, "ok");
});

test("SDK-FETCH-CLOSE-ASYNC-PERMISSIVE: host drain still precedes an ABI that permits recursive task release", { timeout: 5000 }, async (t) => {
  const cleanup = deferred();
  const { scope, start, calls, liveTasks } = await fixture(t, { acceptLiveOwnerClose: true });
  const operation = start();
  unwrap(scope.spawnTask({ label: "recursively-released-generic-task" }));
  await turn();
  const body = calls.network[0].respond(responseBody({ cancel: () => cleanup.promise }));
  unwrap(await operation.response());
  const pending = operation.read();
  await turn();
  const closing = scope.closeAsync();
  await turn();
  assert.equal(calls.scopeClose.length, 0, "a permissive ABI must not allow host ownership to escape the drain");
  assert.equal(liveTasks.size, 2);
  assert.equal(body.readable.locked, true);
  cleanup.resolve();
  unwrap(await closing);
  cancellation(await pending);
  cancellation(await operation.closed);
  assert.equal(calls.scopeClose.length, 1);
  assert.equal(calls.cancel.length, 1, "only the fetch task needs host cancellation");
  assert.equal(calls.join.length, 1, "the ABI recursively releases the unrelated generic task");
  assert.equal(liveTasks.size, 0);
  assert.equal(body.readable.locked, false);
});
