/**
 * Real React renderer + public adapter/SDK + checked-in WASM ownership ledger.
 * Node 24+:
 * npm install --prefix /tmp/asupersync-react-tests --no-save react@19 react-test-renderer@19
 * ASUPERSYNC_REACT_TEST_ROOT=/tmp/asupersync-react-tests node \
 *   --unhandled-rejections=strict --experimental-vm-modules --test \
 *   --test-concurrency=1 scripts/test_react_tasks_wasm.mjs
 *
 * ASUPERSYNC_REACT_TEST_ROOT is optional when React and react-test-renderer are
 * already resolvable from packages/react. No browser engine or Rust rebuild is
 * claimed. The refusal case intercepts only scopeClose; other ABI calls are real.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire, stripTypeScriptTypes } from "node:module";
import { resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { createContext, SourceTextModule, SyntheticModule, runInContext } from "node:vm";

const require = createRequire(process.env.ASUPERSYNC_REACT_TEST_ROOT
  ? resolve(process.env.ASUPERSYNC_REACT_TEST_ROOT, "package.json")
  : new URL("../packages/react/package.json", import.meta.url));
const React = require("react");
const { create, act } = require("react-test-renderer");
globalThis.IS_REACT_ACT_ENVIRONMENT = true;
const files = [
  ["adapter", "packages/react/src/index.ts", true],
  ["@asupersync/browser", "packages/browser/src/index.ts", true],
  ["core-live", "packages/browser-core/index.js", false],
  ["./fetch.js", "packages/browser/src/fetch.ts", true],
  ["./websocket.js", "packages/browser/src/websocket.ts", true],
  ["./stream-pipe.js", "packages/browser/src/stream-pipe.ts", true],
  ["./byte-pipe.js", "packages/browser/src/byte-pipe.ts", true],
  ["./asupersync.js", "packages/browser-core/asupersync.js", false],
  ["./webtransport-streams.js", "packages/browser-core/webtransport-streams.js", false],
];
const sources = new Map(files.map(([, path]) => [
  path, readFileSync(new URL("../" + path, import.meta.url), "utf8"),
]));
const wasmBytes = readFileSync(new URL("../packages/browser-core/asupersync_bg.wasm", import.meta.url));
console.log(JSON.stringify({
  scenario_id: "react-owned-application-tasks-packaged-wasm",
  evidence_scope: "real React renderer, complete adapter/SDK, checked-in JS/WASM, native AbortController and Web Streams",
  no_claim: ["browser engine", "Rust rebuild", "Rust executor dispatch"],
  react_version: React.version,
  source_sha256: Object.fromEntries([...sources].map(([path, source]) => [
    path, createHash("sha256").update(source).digest("hex"),
  ]).concat([["packages/browser-core/asupersync_bg.wasm", createHash("sha256").update(wasmBytes).digest("hex")]])),
}));

const deferred = () => {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
};
const turn = () => new Promise(resolve => setImmediate(resolve));
async function bounded(promise) {
  let timeout;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timeout = setTimeout(() => reject(new Error("React task did not settle")), 3000);
    })]);
  } finally { clearTimeout(timeout); }
}
async function flush() { await act(async () => { await turn(); }); }
async function until(predicate) {
  for (let i = 0; i < 100; i += 1) {
    if (predicate()) return;
    await flush();
  }
  assert.ok(predicate(), "expected React lifecycle transition");
}
function unwrap(outcome) {
  assert.equal(outcome.outcome, "ok", JSON.stringify(outcome));
  return outcome.value;
}
const readyOptions = { eagerInit: false };

async function fixture(t, { closeInterceptor } = {}) {
  const context = createContext({
    console, AbortController, AbortSignal, ArrayBuffer, DataView, Uint8Array, URL,
    EventTarget, MessageEvent, WebSocket, TextEncoder, TextDecoder, Error, DOMException,
    ReadableStream, WritableStream, WebAssembly, Response, Request, structuredClone,
    queueMicrotask, setTimeout, clearTimeout, closeInterceptor,
    window: {}, document: {}, isSecureContext: true,
  });
  const modules = new Map(files.map(([name, path, typescript]) => [
    name, new SourceTextModule(
      typescript ? stripTypeScriptTypes(sources.get(path), { mode: "transform" }) : sources.get(path),
      { context, identifier: fileURLToPath(new URL("../" + path, import.meta.url)) },
    ),
  ]));
  const reactNames = Object.keys(React);
  modules.set("react", new SyntheticModule(reactNames, function () {
    for (const name of reactNames) this.setExport(name, React[name]);
  }, { context, identifier: "real-react" }));
  modules.set("@asupersync/browser-core", new SourceTextModule(
    'export * from "core-live"; export { default } from "core-live";'
    + 'import { scopeClose as realScopeClose } from "core-live";'
    + 'export function scopeClose(handle, version) {'
    + ' const result = globalThis.closeInterceptor?.(handle, version);'
    + ' return result === undefined ? realScopeClose(handle, version) : result;'
    + '}', { context, identifier: "single-refusal-boundary" },
  ));
  modules.set("@asupersync/browser-core/webtransport-streams", modules.get("./webtransport-streams.js"));
  const adapter = modules.get("adapter");
  await adapter.link(specifier => {
    assert.ok(modules.has(specifier), "unexpected import " + specifier);
    return modules.get(specifier);
  });
  await adapter.evaluate();
  context.sdk = modules.get("@asupersync/browser").namespace;
  context.wasmBytes = wasmBytes;
  await runInContext("sdk.init({ module_or_path: wasmBytes })", context);
  const raw = modules.get("./asupersync.js").namespace;
  let tree;
  const release = [];
  const providerReports = [];
  const api = adapter.namespace;
  function wrap(child, strict = false) {
    const provider = React.createElement(api.ReactRuntimeProvider, {
      runtimeOptions: readyOptions,
      onCleanup: report => providerReports.push(report),
    }, child);
    return strict ? React.createElement(React.StrictMode, null, provider) : provider;
  }
  t.after(async () => {
    for (const done of release) done();
    if (tree) await act(async () => { tree.unmount(); });
    await flush();
  });
  return {
    api,
    release,
    providerReports,
    snapshot: () => JSON.parse(raw.browser_operator_snapshot()),
    async render(child, strict = false) {
      await act(async () => {
        if (tree) tree.update(wrap(child, strict));
        else tree = create(wrap(child, strict));
      });
      await flush();
    },
    async unmount() {
      await act(async () => { tree.unmount(); });
      tree = null;
      await flush();
    },
  };
}

test("StrictMode commits one application task and retires its scope before publishing exact values", async t => {
  const f = await fixture(t);
  const expected = Object.freeze({ identity: Symbol("not ABI serializable") });
  const reports = [];
  let calls = 0;
  let state;
  let taskScope;
  function App() {
    state = f.api.useReactTask((_signal, scope) => {
      calls += 1;
      taskScope = scope;
      assert.equal(f.snapshot().tasks.total, 1, "the callback has a real ABI task owner");
      return expected;
    }, [], { label: "strict-task", onCleanup: report => reports.push(report) });
    return null;
  }
  await f.render(React.createElement(App), true);
  await until(() => state.status === "settled");
  assert.equal(calls, 1, "replayed initialization must not start an obsolete callback");
  assert.strictEqual(unwrap(state.outcome), expected);
  unwrap(state.cleanup.outcome);
  assert.equal(state.cleanup.retainedOwners, 0);
  assert.equal(f.snapshot().tasks.total, 0);
  assert.equal(taskScope.close().outcome, "err", "the dedicated scope is already released");
  assert.ok(reports.some(report => report.outcome.outcome === "ok"));
  await f.render(React.createElement(App), true);
  assert.equal(calls, 1, "inline callback and observer identity alone do not restart a task");
});

test("changed dependencies hide stale data and wait for the old callback's async finally", async t => {
  const f = await fixture(t);
  const release = deferred();
  f.release.push(release.resolve);
  const firstStarted = deferred();
  const firstAborted = deferred();
  const calls = [];
  const renders = [];
  let state;
  function App({ version }) {
    state = f.api.useReactTask(async signal => {
      calls.push(version);
      if (version === 1) {
        firstStarted.resolve();
        try {
          await new Promise(resolve => signal.addEventListener("abort", () => {
            firstAborted.resolve();
            resolve();
          }, { once: true }));
        } finally { await release.promise; }
      }
      return version;
    }, [version]);
    renders.push({ version, value: state.outcome?.outcome === "ok" ? state.outcome.value : null });
    return null;
  }
  await f.render(React.createElement(App, { version: 1 }));
  await bounded(firstStarted.promise);
  await f.render(React.createElement(App, { version: 2 }));
  await bounded(firstAborted.promise);
  assert.deepEqual(calls, [1], "replacement admission waits for real callback cleanup");
  assert.equal(state.outcome, null);
  assert.equal(state.status, "running");
  await act(async () => { release.resolve(); await turn(); });
  await until(() => state.status === "settled");
  assert.deepEqual(calls, [1, 2]);
  assert.equal(unwrap(state.outcome), 2);
  assert.ok(renders.filter(render => render.version === 2).every(render => render.value !== 1));
  assert.equal(f.snapshot().tasks.total, 0);
});

test("unmount awaits callback and child stream cleanup before reporting retirement", async t => {
  const f = await fixture(t);
  const callbackGate = deferred();
  const streamGate = deferred();
  const started = deferred();
  const aborted = deferred();
  const streamCancelled = deferred();
  f.release.push(callbackGate.resolve, streamGate.resolve);
  const reports = [];
  let readable;
  let writable;
  let callbacksDone = false;
  function App() {
    f.api.useReactTask(async (signal, scope) => {
      readable = new ReadableStream({
        cancel() { streamCancelled.resolve(); return streamGate.promise; },
      }, { highWaterMark: 0 });
      writable = new WritableStream();
      unwrap(scope.pipeTo(readable, writable));
      started.resolve();
      try {
        await new Promise(resolve => signal.addEventListener("abort", () => {
          aborted.resolve();
          resolve();
        }, { once: true }));
      } finally { await callbackGate.promise; callbacksDone = true; }
    }, [], { onCleanup: report => reports.push(report) });
    return null;
  }
  await f.render(React.createElement(App));
  await bounded(started.promise);
  assert.equal(f.snapshot().tasks.total, 2);
  await f.unmount();
  await bounded(aborted.promise);
  await bounded(streamCancelled.promise);
  assert.equal(reports.length, 0);
  assert.equal(f.providerReports.length, 0);
  assert.equal(callbacksDone, false);
  callbackGate.resolve();
  await flush();
  assert.equal(reports.length, 0, "unfinished child stream retains the task's scope");
  streamGate.resolve();
  await until(() => reports.length > 0 && f.providerReports.length > 0);
  for (const report of [...reports, ...f.providerReports]) {
    unwrap(report.outcome);
    assert.equal(report.retainedOwners, 0);
  }
  assert.equal(callbacksDone, true);
  assert.equal(readable.locked, false);
  assert.equal(writable.locked, false);
  assert.equal(f.snapshot().tasks.total, 0);
});

test("explicit cancellation drains its task while a sibling invocation remains live", async t => {
  const f = await fixture(t);
  const release = deferred();
  const secondRelease = deferred();
  f.release.push(release.resolve, secondRelease.resolve);
  const started = [deferred(), deferred()];
  const signals = [];
  const states = [];
  function Task({ index }) {
    states[index] = f.api.useReactTask(async signal => {
      signals[index] = signal;
      started[index].resolve();
      if (index === 0) {
        await new Promise(resolve => signal.addEventListener("abort", resolve, { once: true }));
        await release.promise;
      } else { await secondRelease.promise; }
      return index;
    }, []);
    return null;
  }
  function App() {
    return React.createElement(React.Fragment, null,
      React.createElement(Task, { index: 0 }), React.createElement(Task, { index: 1 }));
  }
  await f.render(React.createElement(App));
  await bounded(Promise.all(started.map(start => start.promise)));
  let cancelled;
  await act(async () => { cancelled = states[0].cancel(); await turn(); });
  assert.equal(signals[0].aborted, true);
  assert.equal(signals[1].aborted, false);
  assert.equal(states[0].status, "cancelling");
  assert.equal(states[0].outcome, null);
  await act(async () => { release.resolve(); unwrap((await bounded(cancelled)).outcome); });
  await until(() => states[0].status === "settled");
  assert.equal(states[0].outcome.outcome, "cancelled");
  assert.equal(states[1].status, "running");
  assert.equal(f.snapshot().tasks.total, 1);
  await act(async () => { secondRelease.resolve(); await turn(); });
  await until(() => states[1].status === "settled");
  assert.equal(unwrap(states[1].outcome), 1);
  assert.equal(f.snapshot().tasks.total, 0);
});

test("disabling and pre-admission cancellation do not execute the callback", async t => {
  const f = await fixture(t);
  let calls = 0;
  let state;
  function App({ enabled, cancelOnCommit }) {
    state = f.api.useReactTask(() => { calls += 1; return "done"; }, [], { enabled });
    React.useEffect(() => {
      if (cancelOnCommit) void state.cancel();
    }, [enabled, cancelOnCommit]);
    return null;
  }
  await f.render(React.createElement(App, { enabled: false, cancelOnCommit: false }));
  assert.equal(state.status, "idle");
  assert.equal(calls, 0);
  await f.render(React.createElement(App, { enabled: true, cancelOnCommit: true }));
  await until(() => state.status === "settled");
  assert.equal(state.outcome.outcome, "cancelled");
  assert.equal(calls, 0);
  await f.render(React.createElement(App, { enabled: false, cancelOnCommit: false }));
  await f.render(React.createElement(App, { enabled: true, cancelOnCommit: false }));
  await until(() => state.status === "settled");
  assert.equal(unwrap(state.outcome), "done");
  assert.equal(calls, 1);
});

test("cleanup refusal stays separate from the result and retries without rerunning application work", async t => {
  let refuse = true;
  const refusal = { outcome: "err", failure: {
    code: "internal_failure", recoverability: "transient", message: "controlled close refusal",
  } };
  const f = await fixture(t, { closeInterceptor: () => refuse ? refusal : undefined });
  f.release.push(() => { refuse = false; });
  const finalRelease = deferred();
  const finalStarted = deferred();
  f.release.push(finalRelease.resolve);
  let finalSignal;
  let calls = 0;
  let state;
  function App({ version }) {
    state = f.api.useReactTask(async signal => {
      calls += 1;
      if (version === 3) {
        finalSignal = signal;
        finalStarted.resolve();
        await finalRelease.promise;
      }
      return version;
    }, [version]);
    return null;
  }
  await f.render(React.createElement(App, { version: 1 }));
  await until(() => state.status === "settled");
  assert.equal(unwrap(state.outcome), 1);
  assert.strictEqual(state.cleanup.outcome, refusal);
  assert.equal(state.cleanup.retainedOwners, 1);
  const oldReceipt = state.cleanup;
  await f.render(React.createElement(App, { version: 2 }));
  await until(() => state.status === "settled");
  assert.equal(calls, 1, "a refused old owner blocks replacement work");
  assert.strictEqual(state.outcome, refusal);
  assert.strictEqual(state.cleanup.outcome, refusal);
  assert.equal(state.cleanup.retainedOwners, 1);
  refuse = false;
  await act(async () => { unwrap((await bounded(state.cancel())).outcome); });
  assert.equal(state.cleanup.retainedOwners, 0);
  assert.equal(calls, 1, "cleanup retries never rerun work");
  await f.render(React.createElement(App, { version: 3 }));
  await bounded(finalStarted.promise);
  assert.equal(calls, 2);
  unwrap((await bounded(oldReceipt.retry())).outcome);
  assert.equal(finalSignal.aborted, false, "an old receipt never targets a newer generation");
  assert.equal(state.status, "running");
  assert.equal(f.snapshot().tasks.total, 1);
  await act(async () => { finalRelease.resolve(); await turn(); });
  await until(() => state.status === "settled");
  assert.equal(unwrap(state.outcome), 3);
  assert.equal(f.snapshot().tasks.total, 0);
});


test("successful callback data waits for the task scope's remaining child stream to drain", async t => {
  const f = await fixture(t);
  const drain = deferred();
  const cancelStarted = deferred();
  f.release.push(drain.resolve);
  let state;
  let readable;
  let writable;
  function App() {
    state = f.api.useReactTask((_signal, scope) => {
      readable = new ReadableStream({
        cancel() { cancelStarted.resolve(); return drain.promise; },
      }, { highWaterMark: 0 });
      writable = new WritableStream();
      unwrap(scope.pipeTo(readable, writable));
      return "complete";
    }, []);
    return null;
  }
  await f.render(React.createElement(App));
  await bounded(cancelStarted.promise);
  assert.equal(state.status, "running");
  assert.equal(state.outcome, null);
  assert.equal(state.cleanup, null);
  assert.equal(f.snapshot().tasks.total, 1, "the pending child remains owned");
  await act(async () => { drain.resolve(); await turn(); });
  await until(() => state.status === "settled");
  assert.equal(unwrap(state.outcome), "complete");
  unwrap(state.cleanup.outcome);
  assert.equal(f.snapshot().tasks.total, 0);
  assert.equal(readable.locked, false);
  assert.equal(writable.locked, false);
});

test("callback rejection is a terminal panicked outcome after scope retirement", async t => {
  const f = await fixture(t);
  let state;
  let rendered = 0;
  const hostile = { toString() { rendered += 1; throw new Error("do not format thrown values"); } };
  function App() {
    state = f.api.useReactTask(() => Promise.reject(hostile), []);
    return null;
  }
  await f.render(React.createElement(App));
  await until(() => state.status === "settled");
  assert.equal(state.outcome.outcome, "panicked");
  unwrap(state.cleanup.outcome);
  assert.equal(state.cleanup.retainedOwners, 0);
  assert.equal(rendered, 0);
  assert.equal(f.snapshot().tasks.total, 0);
});
