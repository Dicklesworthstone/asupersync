/**
 * React owned-fetch lifecycle regressions (Node 24+):
 * node --unhandled-rejections=strict --experimental-vm-modules --test \
 *   --test-concurrency=1 scripts/test_react_owned_fetch_lifecycle.mjs
 *
 * Executes complete React adapter, browser SDK, fetch adapter and core sources
 * with native WHATWG streams. Only React's hook dispatcher and the generated
 * WASM ABI are intentional doubles; selected bootstrap fault cases replace
 * the runtime factory before allocation. This proves the adapter/SDK host
 * boundary, not actual React rendering, a browser engine or Rust/WASM execution.
 * ASUPERSYNC_REACT_SOURCE selects an untouched old adapter for negative controls.
 * No source file is rewritten by this harness.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";

const paths = {
  react: process.env.ASUPERSYNC_REACT_SOURCE
    ?? fileURLToPath(new URL("../packages/react/src/index.ts", import.meta.url)),
  sdk: process.env.ASUPERSYNC_BROWSER_SDK_SOURCE
    ?? fileURLToPath(new URL("../packages/browser/src/index.ts", import.meta.url)),
  fetch: process.env.ASUPERSYNC_BROWSER_FETCH_SOURCE
    ?? fileURLToPath(new URL("../packages/browser/src/fetch.ts", import.meta.url)),
  core: process.env.ASUPERSYNC_BROWSER_CORE_SOURCE
    ?? fileURLToPath(new URL("../packages/browser-core/index.js", import.meta.url)),
  streams: fileURLToPath(new URL("../packages/browser-core/webtransport-streams.js", import.meta.url)),
};
const sources = Object.fromEntries(Object.entries(paths).map(([name, path]) => [name, readFileSync(path, "utf8")]));
const javaScript = Object.fromEntries(Object.entries(sources).map(([name, source]) => [
  name, ["react", "sdk", "fetch"].includes(name) ? stripTypeScriptTypes(source, { mode: "transform" }) : source,
]));
console.log(JSON.stringify({
  scenario_id: "react-owned-fetch-lifecycle",
  source_sha256: Object.fromEntries(Object.entries(sources).map(([name, source]) => [
    name, createHash("sha256").update(source).digest("hex"),
  ])),
  evidence_scope: "actual React adapter/SDK/fetch/core, native streams, intentional React hook and WASM ABI doubles",
  no_claim: ["React rendering", "browser engine", "Rust/WASM execution"],
}));

const turn = () => new Promise((resolve) => setImmediate(resolve));
const unitJson = '{"outcome":"ok","value":{"kind":"unit"}}';
const refusalJson = JSON.stringify({ outcome: "err", failure: {
  code: "compatibility_rejected", recoverability: "transient", message: "controlled owner refusal",
} });
const url = "https://api.example.test/data";
const grant = (origin = "https://api.example.test") => ({
  allowedOrigins: [origin], allowedMethods: ["GET"], allowCredentials: false, maxHeaderCount: 4,
});
function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}
function ok(outcome) {
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

/** Explicit hook double: committed deps, refs, state, cleanup and effect replay. */
function hookDriver() {
  let current = null;
  const sameDeps = (a, b) => a?.length === b?.length && a.every((value, index) => Object.is(value, b[index]));
  function slot(kind, initialize) {
    assert.ok(current, "hook called outside the intentional dispatcher");
    const index = current.cursor++;
    if (!current.slots[index]) current.slots[index] = { kind, ...initialize() };
    assert.equal(current.slots[index].kind, kind, "hook order changed");
    return [current.slots[index], current, index];
  }
  const hooks = {
    createContext: (initial) => ({ initial, Provider: {} }),
    createElement: (component, props, children) => ({ component, ...props, children }),
    useContext: (context) => current.context ?? context.initial,
    useRef(initial) {
      return slot("ref", () => ({ value: { current: initial } }))[0].value;
    },
    useState(initial) {
      const [state, runner] = slot("state", () => ({ value: typeof initial === "function" ? initial() : initial }));
      return [state.value, (value) => {
        if (!runner.mounted && runner.committed) {
          runner.stateWritesAfterUnmount += 1;
          return;
        }
        const next = typeof value === "function" ? value(state.value) : value;
        if (!Object.is(next, state.value)) {
          state.value = next;
          runner.dirty = true;
        }
      }];
    },
    useMemo(create, deps) {
      const [memo] = slot("memo", () => ({ deps: null }));
      if (!sameDeps(memo.deps, deps)) {
        memo.value = create();
        memo.deps = [...deps];
      }
      return memo.value;
    },
    useCallback(callback, deps) { return hooks.useMemo(() => callback, deps); },
    useEffect(create, deps) {
      const [effect, runner, index] = slot("effect", () => ({ deps: null, cleanup: null, create: null }));
      if (!sameDeps(effect.deps, deps)) runner.pending.push({ index, create, deps: [...deps] });
    },
  };
  function runner(component) {
    const instance = {
      slots: [], cursor: 0, pending: [], props: {}, context: null, output: null,
      mounted: false, committed: false, dirty: false, stateWritesAfterUnmount: 0,
      render(props = instance.props, context = instance.context) {
        instance.props = props;
        instance.context = context;
        instance.cursor = 0;
        instance.pending = [];
        instance.dirty = false;
        const previous = current;
        current = instance;
        try { instance.output = component(props); }
        finally { current = previous; }
        return instance.output;
      },
      commit() {
        instance.mounted = true;
        instance.committed = true;
        for (const pending of instance.pending.splice(0)) {
          const effect = instance.slots[pending.index];
          const cleanup = effect.cleanup;
          effect.cleanup = null;
          cleanup?.();
          effect.deps = pending.deps;
          effect.create = pending.create;
          effect.cleanup = pending.create() ?? null;
        }
      },
      replay() {
        for (const effect of instance.slots.filter((slot) => slot.kind === "effect")) {
          const cleanup = effect.cleanup;
          effect.cleanup = null;
          cleanup?.();
          effect.cleanup = effect.create?.() ?? null;
        }
      },
      unmount() {
        instance.mounted = false;
        for (const effect of instance.slots.filter((slot) => slot.kind === "effect")) {
          const cleanup = effect.cleanup;
          effect.cleanup = null;
          cleanup?.();
        }
      },
    };
    return instance;
  }
  return { hooks, runner };
}

async function fixture(t, options = {}) {
  const calls = {
    bootstrap: [], runtimeCreate: [], scopeEnter: [], scopeClose: [], runtimeClose: [],
    spawn: [], cancel: [], join: [], network: [], order: [],
  };
  const controls = { scopeClose: null, runtimeClose: null, taskCancel: unitJson, taskJoin: null };
  const parents = new Map();
  const regions = new Map();
  const runtimes = new Map();
  const liveTasks = new Map();
  const createdRuntimes = [];
  const handles = [];
  const gates = [];
  const key = (raw) => [raw.kind, raw.slot, raw.generation, raw.owner_token].join(":");
  let nextRuntime = 1;
  let nextRegion = 100;
  let nextTask = 1000;
  function ownedBy(scope, owner) {
    let current = key(scope);
    while (current !== undefined) {
      if (current === key(owner)) return true;
      current = parents.get(current);
    }
    return false;
  }
  function closeOwner(raw, override) {
    const exists = raw.kind === "runtime" ? runtimes.has(key(raw)) : regions.has(key(raw));
    if (!exists) return refusalJson;
    const live = [...liveTasks.values()].some((scope) => ownedBy(scope, raw));
    const result = override ?? (live ? refusalJson : unitJson);
    if (JSON.parse(result).outcome === "ok") {
      for (const region of [...regions.values()].filter((value) => ownedBy(value, raw))) {
        regions.delete(key(region));
        parents.delete(key(region));
      }
      if (raw.kind === "runtime") runtimes.delete(key(raw));
    }
    return result;
  }
  function hostFetch(input, init) {
    const headers = deferred();
    const request = {
      url: String(input), init, headers, aborts: 0, response: null,
      respond(body) {
        const response = new Response(body, { status: 200 });
        Object.defineProperty(response, "url", { value: String(input) });
        request.response = response;
        headers.resolve(response);
      },
    };
    init.signal.addEventListener("abort", () => {
      request.aborts += 1;
      if (!request.response) headers.reject(new DOMException("controlled fetch abort", "AbortError"));
    }, { once: true });
    calls.network.push(request);
    return headers.promise;
  }
  const context = createContext({
    AbortController, ArrayBuffer, Uint8Array, URL, TextEncoder, TextDecoder,
    ReadableStream, WritableStream, Response, Headers, Request, WebAssembly,
    Error, TypeError, RangeError, DOMException, structuredClone, queueMicrotask,
    setTimeout, clearTimeout, window: {}, document: {}, isSecureContext: true,
    fetch: hostFetch,
  });
  const names = [
    "default", "abi_fingerprint", "abi_version", "fetch_request",
    "runtime_close", "runtime_create", "scope_close", "scope_enter",
    "task_cancel", "task_join", "task_spawn", "websocket_cancel",
    "websocket_close", "websocket_open", "websocket_recv", "websocket_send",
  ];
  const rawHandle = (kind, slot) => ({ kind, slot, generation: 1, owner_token: "42" });
  const implementations = {
    default: async () => {},
    abi_fingerprint: () => "4558451663113424898",
    abi_version: () => '{"major":1,"minor":0}',
    runtime_create: (request) => {
      const value = rawHandle("runtime", nextRuntime++);
      calls.runtimeCreate.push(JSON.parse(request));
      calls.order.push(["runtime_create", key(value)]);
      runtimes.set(key(value), value);
      return JSON.stringify(value);
    },
    scope_enter: (request) => {
      const parsed = JSON.parse(request);
      const value = rawHandle("region", nextRegion++);
      calls.scopeEnter.push(parsed);
      calls.order.push(["scope_enter", key(value)]);
      parents.set(key(value), key(parsed.parent));
      regions.set(key(value), value);
      return JSON.stringify(value);
    },
    task_spawn: (request) => {
      const parsed = JSON.parse(request);
      const value = rawHandle("task", nextTask++);
      calls.spawn.push(parsed);
      liveTasks.set(key(value), parsed.scope);
      return JSON.stringify(value);
    },
    task_cancel: (request) => { calls.cancel.push(JSON.parse(request)); return controls.taskCancel; },
    task_join: (task, outcome) => {
      calls.join.push({ task: JSON.parse(task), outcome: JSON.parse(outcome) });
      if (controls.taskJoin !== null) return controls.taskJoin;
      liveTasks.delete(key(JSON.parse(task)));
      return outcome;
    },
    scope_close: (scope) => {
      const parsed = JSON.parse(scope);
      calls.scopeClose.push(parsed);
      calls.order.push(["scope_close", key(parsed)]);
      return closeOwner(parsed, controls.scopeClose);
    },
    runtime_close: (runtime) => {
      const parsed = JSON.parse(runtime);
      calls.runtimeClose.push(parsed);
      calls.order.push(["runtime_close", key(parsed)]);
      return closeOwner(parsed, controls.runtimeClose);
    },
  };
  const bindings = new SyntheticModule(names, function () {
    for (const name of names) this.setExport(name, implementations[name] ?? (() => {
      throw new Error("Unexpected WASM ABI call: " + name);
    }));
  }, { context, identifier: "intentional-wasm-owner-ledger" });
  const modules = Object.fromEntries(["sdk", "fetch", "core", "streams"].map((name) => [
    name, new SourceTextModule(javaScript[name], { context, identifier: paths[name] }),
  ]));
  await modules.sdk.link((specifier) => {
    if (specifier === "@asupersync/browser-core") return modules.core;
    if (specifier === "./fetch.js") return modules.fetch;
    if (specifier === "@asupersync/browser-core/webtransport-streams"
      || specifier === "./webtransport-streams.js") return modules.streams;
    assert.equal(specifier, "./asupersync.js");
    return bindings;
  });
  await modules.sdk.evaluate();
  const sdk = modules.sdk.namespace;
  const factory = async (runtimeOptions) => {
    const request = { index: calls.bootstrap.length, options: runtimeOptions };
    calls.bootstrap.push(request);
    const run = async () => {
      const outcome = await sdk.createBrowserRuntime(runtimeOptions);
      if (outcome.outcome === "ok") createdRuntimes.push(outcome.value);
      return outcome;
    };
    return options.bootstrap ? options.bootstrap(request, run) : run();
  };
  const browser = new SyntheticModule(Object.keys(sdk), function () {
    for (const name of Object.keys(sdk)) this.setExport(name, name === "createBrowserRuntime" ? factory : sdk[name]);
  }, { context, identifier: "actual-sdk-with-observable-bootstrap" });
  const driver = hookDriver();
  const react = new SyntheticModule(Object.keys(driver.hooks), function () {
    for (const [name, value] of Object.entries(driver.hooks)) this.setExport(name, value);
  }, { context, identifier: "intentional-react-hook-dispatcher" });
  const module = new SourceTextModule(javaScript.react, { context, identifier: paths.react });
  await module.link((specifier) => {
    if (specifier === "@asupersync/browser") return browser;
    assert.equal(specifier, "react");
    return react;
  });
  await module.evaluate();
  const adapter = module.namespace;
  const provider = driver.runner(adapter.ReactRuntimeProvider);
  const scopes = [];
  const authority = options.authority ?? grant();
  provider.render({
    children: null, runtimeOptions: { fetchAuthority: authority, ...options.runtimeOptions },
    onCleanup: options.onCleanup,
  });
  provider.commit();

  async function step() {
    await turn();
    if (provider.mounted && provider.dirty) {
      provider.render();
      provider.commit();
    }
    for (const scope of scopes) {
      if (scope.mounted && (scope.dirty || scope.context !== provider.output.value)) {
        scope.render(scope.props, provider.output.value);
        scope.commit();
      }
    }
  }
  async function until(predicate, message = "adapter did not reach the required state") {
    for (let i = 0; i < 40; i += 1) {
      if (predicate()) return;
      await step();
    }
    assert.ok(predicate(), message);
  }
  function mountScope(scopeOptions = {}, lifecycle = false) {
    const hook = lifecycle ? adapter.useReactScopeLifecycle : adapter.useReactScope;
    assert.equal(typeof hook, "function");
    const scope = driver.runner(hook);
    scope.render(scopeOptions, provider.output.value);
    scope.commit();
    scopes.push(scope);
    return scope;
  }
  function updateProvider(runtimeOptions, commit = true) {
    provider.render({ ...provider.props, runtimeOptions });
    for (const scope of scopes) if (scope.mounted) scope.render(scope.props, provider.output.value);
    if (commit) {
      provider.commit();
      for (const scope of scopes) if (scope.mounted) scope.commit();
    }
  }
  function updateScope(scope, scopeOptions, commit = true) {
    scope.render(scopeOptions, provider.output.value);
    if (commit) scope.commit();
  }
  function start(scope, request = {}) {
    const handle = ok(scope.fetch({ url, ...request }));
    handles.push(handle);
    return handle;
  }
  async function parkedFetch(scope) {
    const previousRequests = calls.network.length;
    const handle = start(scope);
    await until(() => calls.network.length > previousRequests);
    const request = calls.network.at(-1);
    const release = deferred();
    gates.push(release);
    const body = { cancels: 0, pulls: 0 };
    const stream = new ReadableStream({
      pull() { body.pulls += 1; },
      cancel() { body.cancels += 1; return release.promise; },
    }, { highWaterMark: 0 });
    request.respond(stream);
    ok(await handle.response());
    const read = handle.read();
    await until(() => body.pulls === 1, "native body read did not park");
    return { handle, request, body, read, release: () => release.resolve() };
  }
  t.after(async () => {
    controls.scopeClose = null;
    controls.runtimeClose = null;
    controls.taskCancel = unitJson;
    controls.taskJoin = null;
    for (const gate of gates) gate.resolve();
    for (const request of calls.network) {
      if (!request.response) request.headers.reject(new DOMException("fixture teardown", "AbortError"));
    }
    for (const scope of scopes) if (scope.mounted) scope.unmount();
    if (provider.mounted) provider.unmount();
    await Promise.allSettled(handles.map((handle) => handle.cancel("fixture teardown")));
    await turn();
    await Promise.allSettled(createdRuntimes.map((runtime) => runtime.closeAsync()));
  });
  return {
    adapter, sdk, driver, provider, scopes, calls, controls, authority,
    regions, runtimes, liveTasks, mountScope, updateProvider, updateScope,
    until, step, start, parkedFetch,
    context: () => provider.output.value,
    ready: () => until(() => provider.output.value.status === "ready"),
    unitJson, refusalJson,
  };
}

async function readyScope(f, options = {}, lifecycle = false) {
  const scope = f.mountScope(options, lifecycle);
  await f.until(() => scope.output.status === "ready", "scope did not become ready");
  return scope;
}

test("REACT-UNMOUNT: component cleanup drains a parked native fetch before closing owners", { timeout: 5000 }, async (t) => {
  const runtimeReports = [];
  const scopeReports = [];
  const f = await fixture(t, { onCleanup: (report) => runtimeReports.push(report) });
  await f.ready();
  const scope = await readyScope(f, { label: "owned", onCleanup: (report) => scopeReports.push(report) });
  const fetch = await f.parkedFetch(scope.output.scope);

  f.provider.unmount();
  scope.unmount();
  await f.until(() => fetch.body.cancels === 1, "unmount must request structured body cleanup");
  assert.equal(fetch.request.aborts, 1);
  assert.equal(f.calls.scopeClose.length, 0, "scope ABI close must wait for host cleanup");
  assert.equal(f.calls.runtimeClose.length, 0, "parent ABI close must wait for child cleanup");
  assert.equal(runtimeReports.length, 0);
  assert.equal(scopeReports.length, 0);

  fetch.release();
  cancellation(await fetch.read);
  await f.until(() => runtimeReports.length === 1 && scopeReports.length === 1);
  for (const report of [...scopeReports, ...runtimeReports]) {
    ok(report.outcome);
    assert.equal(report.retainedOwners, 0);
  }
  assert.equal(f.calls.scopeClose.length, 1);
  assert.equal(f.calls.runtimeClose.length, 1);
  assert.equal(f.calls.cancel.length, 1);
  assert.equal(f.calls.join.length, 1);
  assert.equal(f.liveTasks.size, 0);
  assert.equal(f.regions.size, 0);
  assert.equal(f.runtimes.size, 0);
  const closes = f.calls.order.filter(([operation]) => operation.endsWith("_close")).map(([operation]) => operation);
  assert.deepEqual(closes, ["scope_close", "runtime_close"]);
  assert.equal(scope.stateWritesAfterUnmount, 0);
  assert.equal(f.provider.stateWritesAfterUnmount, 0);
});

test("REACT-AUTHORITY: prop rotation hides the old grant before effects and waits for retirement", { timeout: 5000 }, async (t) => {
  const f = await fixture(t);
  await f.ready();
  const scope = await readyScope(f, { label: "authority" });
  const oldRuntime = f.context().runtime;
  const oldScope = scope.output.scope;
  const fetch = await f.parkedFetch(oldScope);
  const replacementGrant = grant("https://replacement.example.test");

  f.updateProvider({ fetchAuthority: replacementGrant }, false);
  assert.equal(f.context().runtime, null, "render must not expose the previous authority as ready");
  assert.notEqual(f.context().status, "ready");
  assert.equal(scope.output.scope, null);
  f.provider.commit();
  scope.commit();
  await f.until(() => fetch.body.cancels === 1);
  for (let index = 0; index < 3; index += 1) await f.step();
  assert.equal(f.calls.bootstrap.length, 1, "replacement bootstrap waits for actual old-owner cleanup");
  assert.equal(f.calls.runtimeCreate.length, 1);
  assert.equal(f.calls.scopeEnter.length, 1);

  fetch.release();
  cancellation(await fetch.read);
  await f.until(() => f.context().status === "ready" && scope.output.status === "ready");
  assert.notEqual(f.context().runtime, oldRuntime);
  assert.notEqual(scope.output.scope, oldScope);
  assert.equal(f.calls.runtimeCreate.length, 2);
  assert.equal(f.calls.scopeEnter.length, 2);
  const requests = f.calls.network.length;
  failure(scope.output.scope.fetch({ url }), "capability_denied");
  assert.equal(f.calls.network.length, requests, "old origin denied before host dispatch");
  const authorized = f.start(scope.output.scope, { url: "https://replacement.example.test/data" });
  await f.until(() => f.calls.network.length === requests + 1);
  cancellation(await authorized.cancel("authority test complete"));
  assert.equal(f.calls.scopeClose.length, 1);
  assert.equal(f.calls.runtimeClose.length, 1);
});

test("scope label replacement waits for the old stream and does not overlap scope allocation", { timeout: 5000 }, async (t) => {
  const f = await fixture(t);
  await f.ready();
  const scope = await readyScope(f, { label: "old" });
  const oldScope = scope.output.scope;
  const fetch = await f.parkedFetch(oldScope);

  f.updateScope(scope, { label: "new" }, false);
  assert.equal(scope.output.scope, null);
  assert.equal(scope.output.status, "opening");
  scope.commit();
  await f.until(() => fetch.body.cancels === 1);
  assert.equal(f.calls.scopeEnter.length, 1);
  assert.equal(f.calls.scopeClose.length, 0);
  fetch.release();
  cancellation(await fetch.read);
  await f.until(() => scope.output.status === "ready");
  assert.notEqual(scope.output.scope, oldScope);
  assert.equal(f.calls.scopeEnter.length, 2);
  assert.equal(f.calls.scopeClose.length, 1);
  assert.equal(f.calls.runtimeClose.length, 0);
});

test("StrictMode effect replay retires a late bootstrap before admitting its replacement", { timeout: 5000 }, async (t) => {
  const release = deferred();
  t.after(() => release.resolve());
  const f = await fixture(t, {
    bootstrap: async (request, run) => {
      if (request.index === 0) await release.promise;
      return run();
    },
  });
  await f.until(() => f.calls.bootstrap.length === 1);
  f.provider.replay();
  for (let index = 0; index < 3; index += 1) await f.step();
  assert.equal(f.calls.bootstrap.length, 1);
  assert.equal(f.calls.runtimeCreate.length, 0);
  assert.equal(f.context().runtime, null);

  release.resolve();
  await f.ready();
  assert.equal(f.calls.bootstrap.length, 2);
  assert.equal(f.calls.runtimeCreate.length, 2);
  assert.equal(f.calls.runtimeClose.length, 1);
  assert.equal(f.runtimes.size, 1);
  assert.equal(f.context().error, null);
  assert.deepEqual(f.calls.order.map(([operation]) => operation), [
    "runtime_create", "runtime_close", "runtime_create",
  ]);
});

test("a rejected stale bootstrap cannot fail the replacement generation", { timeout: 5000 }, async (t) => {
  const rejectFirst = deferred();
  t.after(() => rejectFirst.resolve());
  const f = await fixture(t, {
    bootstrap: (request, run) => request.index === 0 ? rejectFirst.promise.then(run) : run(),
  });
  await f.until(() => f.calls.bootstrap.length === 1);
  f.context().reload();
  await f.step();
  assert.equal(f.calls.bootstrap.length, 1);
  rejectFirst.reject(new Error("stale controlled bootstrap rejection"));
  await f.ready();
  assert.equal(f.calls.bootstrap.length, 2);
  assert.equal(f.calls.runtimeCreate.length, 1);
  assert.equal(f.calls.runtimeClose.length, 0);
  assert.equal(f.context().error, null);
  assert.equal(f.runtimes.size, 1);
});

test("late bootstrap after unmount is closed without publishing state", { timeout: 5000 }, async (t) => {
  const release = deferred();
  const reports = [];
  t.after(() => release.resolve());
  const f = await fixture(t, {
    onCleanup: (report) => reports.push(report),
    bootstrap: async (_request, run) => { await release.promise; return run(); },
  });
  await f.until(() => f.calls.bootstrap.length === 1);
  f.provider.unmount();
  assert.equal(reports.length, 0);
  release.resolve();
  await f.until(() => reports.length === 1);
  ok(reports[0].outcome);
  assert.equal(reports[0].retainedOwners, 0);
  assert.equal(f.calls.runtimeCreate.length, 1);
  assert.equal(f.calls.runtimeClose.length, 1);
  assert.equal(f.runtimes.size, 0);
  assert.equal(f.provider.stateWritesAfterUnmount, 0);
});

test("scope close refusal retains the owner, blocks replacement and supports snapshot-only retry", { timeout: 5000 }, async (t) => {
  const reports = [];
  const f = await fixture(t);
  await f.ready();
  const scope = await readyScope(f, { label: "refused", onCleanup: (report) => reports.push(report) }, true);
  f.controls.scopeClose = f.refusalJson;
  const report = await scope.output.closeAsync();
  failure(report.outcome, "compatibility_rejected");
  assert.equal(report.retainedOwners, 1);
  await f.step();
  assert.equal(scope.output.scope, null);
  assert.equal(scope.output.status, "failed");
  assert.equal(f.regions.size, 1);

  f.updateScope(scope, { label: "blocked-replacement" });
  await f.until(() => scope.output.status === "failed");
  assert.equal(f.calls.scopeEnter.length, 1, "refused ownership cannot be abandoned for replacement");
  f.controls.scopeClose = null;
  const retried = await report.retry();
  ok(retried.outcome);
  assert.equal(retried.retainedOwners, 0);
  assert.equal(f.regions.size, 0);

  f.updateScope(scope, { label: "after-retry" });
  await f.until(() => scope.output.status === "ready");
  assert.equal(f.calls.scopeEnter.length, 2);
  const currentScope = scope.output.scope;
  const closedCount = f.calls.scopeClose.length;
  ok((await report.retry()).outcome);
  assert.equal(f.calls.scopeClose.length, closedCount, "old receipt cannot close the new generation");
  assert.equal(scope.output.scope, currentScope);
  assert.equal(f.regions.size, 1);
  assert.ok(reports.length >= 1);
});

test("a refused child retains the parent and parent retry closes child before runtime", { timeout: 5000 }, async (t) => {
  const f = await fixture(t);
  await f.ready();
  await readyScope(f, { label: "child" }, true);
  f.controls.scopeClose = f.refusalJson;
  const report = await f.context().closeAsync();
  failure(report.outcome, "compatibility_rejected");
  assert.equal(report.retainedOwners, 2);
  assert.equal(f.calls.runtimeClose.length, 0);
  assert.equal(f.runtimes.size, 1);
  assert.equal(f.regions.size, 1);

  f.controls.scopeClose = null;
  const retried = await report.retry();
  ok(retried.outcome);
  assert.equal(retried.retainedOwners, 0);
  assert.equal(f.calls.runtimeClose.length, 1);
  assert.equal(f.regions.size, 0);
  assert.equal(f.runtimes.size, 0);
});

for (const target of ["runtime", "scope"]) {
  test("explicit " + target + " close then unmount cannot publish a late refusal", { timeout: 5000 }, async (t) => {
    const f = await fixture(t);
    await f.ready();
    const scope = await readyScope(f, { label: "pending-close" }, true);
    const fetch = await f.parkedFetch(scope.output.scope);
    f.controls[target === "runtime" ? "runtimeClose" : "scopeClose"] = f.refusalJson;
    const completion = target === "runtime" ? f.context().closeAsync() : scope.output.closeAsync();
    f.provider.unmount();
    scope.unmount();
    await f.until(() => fetch.body.cancels === 1);
    fetch.release();
    cancellation(await fetch.read);
    const report = await completion;
    failure(report.outcome, "compatibility_rejected");
    assert.equal(report.retainedOwners, 1);
    await f.step();
    assert.equal(f.provider.stateWritesAfterUnmount, 0);
    assert.equal(scope.stateWritesAfterUnmount, 0);
    f.controls.runtimeClose = null;
    f.controls.scopeClose = null;
    ok((await report.retry()).outcome);
  });
}

test("parent retirement sweeps raw-runtime work admitted while a child drain is pending", { timeout: 5000 }, async (t) => {
  const f = await fixture(t);
  await f.ready();
  const runtime = f.context().runtime;
  const scope = await readyScope(f, { label: "hook-child" });
  const fetch = await f.parkedFetch(scope.output.scope);
  const completion = f.context().closeAsync();
  await f.until(() => fetch.body.cancels === 1);
  assert.equal(f.calls.runtimeClose.length, 0);

  // The React coordinator gates hooks here. The raw runtime is not yet at its
  // SDK close boundary; independent raw callers are swept by that later close.
  const direct = ok(runtime.enterScope("direct-during-child-drain"));
  const pending = f.start(direct);
  await f.until(() => f.calls.network.length === 2);
  const directRequest = f.calls.network[1];
  assert.equal(directRequest.aborts, 0);
  fetch.release();
  cancellation(await fetch.read);
  const report = await completion;
  ok(report.outcome);
  cancellation(await pending.response());
  assert.equal(directRequest.aborts, 1);
  assert.equal(report.retainedOwners, 0);
  assert.equal(f.liveTasks.size, 0);
  assert.equal(f.regions.size, 0);
  assert.equal(f.runtimes.size, 0);
  assert.equal(f.calls.cancel.length, 2);
  assert.equal(f.calls.join.length, 2);
  assert.equal(f.calls.runtimeClose.length, 1);
});

test("semantic version normalization avoids runtime and scope churn, including null defaults", { timeout: 5000 }, async (t) => {
  const f = await fixture(t);
  await f.ready();
  const scope = await readyScope(f, { label: "stable" });
  const runtime = f.context().runtime;
  const region = scope.output.scope;
  f.updateProvider({ fetchAuthority: f.authority, consumerVersion: null });
  f.updateScope(scope, { label: "stable", consumerVersion: null });
  for (let index = 0; index < 3; index += 1) await f.step();
  assert.equal(f.context().runtime, runtime);
  assert.equal(scope.output.scope, region);
  assert.equal(f.calls.runtimeCreate.length, 1);
  assert.equal(f.calls.scopeEnter.length, 1);
  assert.equal(f.calls.runtimeClose.length, 0);
  assert.equal(f.calls.scopeClose.length, 0);

  f.updateProvider({ fetchAuthority: f.authority, consumerVersion: { major: 1, minor: 0 } });
  await f.until(() => f.context().status === "ready" && scope.output.status === "ready");
  const versionedRuntime = f.context().runtime;
  const versionedScope = scope.output.scope;
  const counts = [f.calls.runtimeCreate.length, f.calls.scopeEnter.length, f.calls.runtimeClose.length, f.calls.scopeClose.length];
  f.updateProvider({ fetchAuthority: f.authority, consumerVersion: { major: 1, minor: 0 } });
  f.updateScope(scope, { label: "stable", consumerVersion: undefined });
  for (let index = 0; index < 3; index += 1) await f.step();
  assert.equal(f.context().runtime, versionedRuntime);
  assert.equal(scope.output.scope, versionedScope);
  assert.deepEqual([f.calls.runtimeCreate.length, f.calls.scopeEnter.length, f.calls.runtimeClose.length, f.calls.scopeClose.length], counts);
});

test("legacy close remains void, drains asynchronously and isolates throwing observers", { timeout: 5000 }, async (t) => {
  const reports = [];
  const f = await fixture(t);
  await f.ready();
  const scope = await readyScope(f, {
    onCleanup: (report) => { reports.push(report); throw new Error("observer cannot veto cleanup"); },
  });
  const fetch = await f.parkedFetch(scope.output.scope);
  assert.equal(scope.output.close(), undefined);
  await f.until(() => fetch.body.cancels === 1);
  assert.equal(f.calls.scopeClose.length, 0);
  fetch.release();
  cancellation(await fetch.read);
  await f.until(() => reports.length === 1);
  ok(reports[0].outcome);
  assert.equal(reports[0].retainedOwners, 0);
  await f.step();
  assert.equal(scope.output.scope, null);
  assert.equal(f.calls.scopeClose.length, 1);
  assert.equal(f.calls.runtimeClose.length, 0);
});

test("cleanup reports use the latest committed observers without restarting owners", { timeout: 5000 }, async (t) => {
  const observations = [];
  const observe = (label) => (report) => observations.push({ label, report });
  const f = await fixture(t, { onCleanup: observe("initial-runtime") });
  await f.ready();
  const scope = await readyScope(f, { onCleanup: observe("initial-scope") });
  const runtime = f.context().runtime;
  const region = scope.output.scope;

  f.provider.render({ ...f.provider.props, onCleanup: observe("updated-runtime") });
  f.provider.commit();
  scope.render({ ...scope.props, onCleanup: observe("updated-scope") }, f.context());
  scope.commit();
  await f.step();
  assert.equal(f.context().runtime, runtime);
  assert.equal(scope.output.scope, region);
  assert.equal(f.calls.runtimeCreate.length, 1);
  assert.equal(f.calls.scopeEnter.length, 1);
  assert.equal(f.calls.scopeClose.length, 0);
  assert.equal(f.calls.runtimeClose.length, 0);

  const fetch = await f.parkedFetch(region);
  const completion = f.context().closeAsync();
  await f.until(() => fetch.body.cancels === 1);
  f.provider.render({ ...f.provider.props, onCleanup: observe("committed-runtime") });
  f.provider.commit();
  scope.render({ ...scope.props, onCleanup: observe("committed-scope") }, f.context());
  scope.commit();
  // A render that never commits must not change the cleanup recipient.
  f.provider.render({ ...f.provider.props, onCleanup: observe("speculative-runtime") });
  scope.render({ ...scope.props, onCleanup: observe("speculative-scope") }, f.context());
  f.provider.unmount();
  scope.unmount();
  fetch.release();
  cancellation(await fetch.read);
  ok((await completion).outcome);
  await f.until(() => observations.some(({ label }) => label === "committed-runtime")
    && observations.some(({ label }) => label === "committed-scope"));
  assert.ok(observations.every(({ label }) => label.startsWith("committed-")));
  assert.ok(observations.every(({ report }) => report.outcome.outcome === "ok" && report.retainedOwners === 0));
  assert.equal(f.calls.runtimeCreate.length, 1);
  assert.equal(f.calls.scopeEnter.length, 1);
  assert.equal(f.calls.scopeClose.length, 1);
  assert.equal(f.calls.runtimeClose.length, 1);
  assert.equal(f.liveTasks.size, 0);
  assert.equal(f.regions.size, 0);
  assert.equal(f.runtimes.size, 0);
  assert.equal(f.provider.stateWritesAfterUnmount, 0);
  assert.equal(scope.stateWritesAfterUnmount, 0);
});
