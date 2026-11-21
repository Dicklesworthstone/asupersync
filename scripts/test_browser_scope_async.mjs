/**
 * Async scope brackets over the actual SDK, checked-in WASM ownership ledger,
 * and Node's native Web Streams. This is not browser-engine execution or a
 * Rust rebuild. Refusal cases inject only the scope-close ABI response.
 * node --unhandled-rejections=strict --experimental-vm-modules --test scripts/test_browser_scope_async.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { createContext, SourceTextModule, runInContext } from "node:vm";

const files = [
  ["sdk", "packages/browser/src/index.ts", true],
  ["core-live", "packages/browser-core/index.js", false],
  ["./fetch.js", "packages/browser/src/fetch.ts", true],
  ["./websocket.js", "packages/browser/src/websocket.ts", true],
  ["./stream-pipe.js", "packages/browser/src/stream-pipe.ts", true],
  ["./asupersync.js", "packages/browser-core/asupersync.js", false],
  ["./webtransport-streams.js", "packages/browser-core/webtransport-streams.js", false],
];
const inputs = new Map();
const hashes = {};
for (const [, path] of files) {
  const bytes = readFileSync(new URL(`../${path}`, import.meta.url));
  inputs.set(path, bytes.toString());
  hashes[path] = createHash("sha256").update(bytes).digest("hex");
}
const wasmPath = "packages/browser-core/asupersync_bg.wasm";
const wasmBytes = readFileSync(new URL(`../${wasmPath}`, import.meta.url));
hashes[wasmPath] = createHash("sha256").update(wasmBytes).digest("hex");
console.log(JSON.stringify({
  scenario_id: "browser-async-scope-packaged-wasm",
  evidence_scope: "actual SDK, checked-in JS/WASM ownership ledger, native Node Web Streams",
  no_claim: ["browser-engine execution", "Rust rebuild", "Rust executor dispatch"],
  source_sha256: hashes,
}));

async function loadSdk(closeInterceptor) {
  const context = createContext({
    console, AbortController, AbortSignal, ArrayBuffer, DataView, Uint8Array, URL,
    EventTarget, MessageEvent, WebSocket, TextEncoder, TextDecoder,
    ReadableStream, WritableStream, WebAssembly, Response, Request, structuredClone,
    queueMicrotask, setTimeout, clearTimeout,
    window: {}, document: {}, isSecureContext: true,
    closeInterceptor,
  });
  const modules = new Map();
  for (const [name, path, typescript] of files) {
    const source = inputs.get(path);
    modules.set(name, new SourceTextModule(
      typescript ? stripTypeScriptTypes(source, { mode: "transform" }) : source,
      { context, identifier: fileURLToPath(new URL(`../${path}`, import.meta.url)) },
    ));
  }
  // Every operation except an explicitly injected close refusal still reaches
  // the packaged ABI. Successful closes are never fabricated by this harness.
  modules.set("@asupersync/browser-core", new SourceTextModule(`
    export * from "core-live";
    export { default } from "core-live";
    import { scopeClose as realScopeClose } from "core-live";
    export function scopeClose(handle, version) {
      const intercepted = globalThis.closeInterceptor?.(handle, version);
      return intercepted === undefined ? realScopeClose(handle, version) : intercepted;
    }
  `, { context, identifier: "scope-close-refusal-boundary" }));
  modules.set("@asupersync/browser-core/webtransport-streams", modules.get("./webtransport-streams.js"));
  const entry = modules.get("sdk");
  await entry.link((specifier) => {
    assert.ok(modules.has(specifier), `unexpected module import ${specifier}`);
    return modules.get(specifier);
  });
  await entry.evaluate();
  context.sdk = entry.namespace;
  context.wasmBytes = wasmBytes;
  await runInContext("sdk.init({ module_or_path: wasmBytes })", context);
  const raw = modules.get("./asupersync.js").namespace;
  return { sdk: entry.namespace, snapshot: () => JSON.parse(raw.browser_operator_snapshot()) };
}

const ok = value => ({ outcome: "ok", value });
function unwrap(outcome) {
  assert.equal(outcome.outcome, "ok", JSON.stringify(outcome));
  return outcome.value;
}
function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}
const observe = promise => promise.then(
  value => ({ kind: "returned", value }), error => ({ kind: "threw", error }),
);
const nextTurn = () => new Promise(resolve => setImmediate(resolve));
async function bounded(promise) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("async scope operation did not settle")), 2000);
    })]);
  } finally { clearTimeout(timer); }
}
async function fixture(t, {
  closeInterceptor, beforeCleanup = () => {}, runtimeAlreadyClosed = () => false,
} = {}) {
  const loaded = await loadSdk(closeInterceptor);
  const runtime = unwrap(await loaded.sdk.createBrowserRuntime({ eagerInit: false }));
  t.after(async () => {
    beforeCleanup();
    if (!runtimeAlreadyClosed()) unwrap(await bounded(runtime.closeAsync()));
  });
  return { ...loaded, runtime };
}
function quietPipe(scope) {
  const cancelled = deferred();
  const aborted = deferred();
  let cancellations = 0;
  let aborts = 0;
  const readable = new ReadableStream({
    cancel() { cancellations += 1; cancelled.resolve(); },
  }, { highWaterMark: 0 });
  const writable = new WritableStream({
    abort() { aborts += 1; aborted.resolve(); },
  });
  const handle = unwrap(scope.pipeTo(readable, writable));
  return {
    handle, readable, writable, cancelled, aborted,
    counts: () => ({ cancellations, aborts }),
  };
}

test("refused child admission never invokes the body or closes an existing owner", async (t) => {
  let bodyCalls = 0;
  let closeCalls = 0;
  const { runtime, snapshot } = await fixture(t, {
    closeInterceptor() { closeCalls += 1; return undefined; },
  });
  const parent = unwrap(runtime.enterScope("admission-refusal-parent"));
  const existing = quietPipe(parent);
  for (const owner of [runtime, parent]) {
    const result = await bounded(owner.withScopeAsync(() => {
      bodyCalls += 1;
      return ok("must not run");
    }, { consumerVersion: { major: 65_535, minor: 0 } }));
    assert.equal(result.outcome, "err");
    assert.equal(result.failure.code, "compatibility_rejected");
  }
  assert.equal(bodyCalls, 0);
  assert.equal(closeCalls, 0, "admission refusal has no child cleanup target");
  assert.equal(snapshot().tasks.total, 1);
  assert.deepEqual(existing.counts(), { cancellations: 0, aborts: 0 });
  assert.equal(existing.readable.locked, true);
  assert.equal(existing.writable.locked, true);
  unwrap(await bounded(parent.closeAsync()));
  assert.equal(snapshot().tasks.total, 0);
});

test("withScopeAsync returns the exact callback Outcome after releasing its child", async (t) => {
  const { runtime, snapshot } = await fixture(t);
  const parent = unwrap(runtime.enterScope("parent"));
  const outcomes = [
    Object.freeze(ok({ marker: "body value" })),
    Object.freeze({ outcome: "err", failure: { code: "internal_failure", recoverability: "transient", message: "body error" } }),
    Object.freeze({ outcome: "cancelled", cancellation: {
      kind: "user", phase: "completed", origin_region: "body", origin_task: null,
      timestamp_nanos: 0, message: "body cancelled", truncated: false,
    } }),
    Object.freeze({ outcome: "panicked", message: "body panic outcome" }),
  ];
  for (const owner of [runtime, parent]) {
    for (const expected of outcomes) {
      let child;
      const actual = await bounded(owner.withScopeAsync(scope => {
        child = scope;
        return expected;
      }, { label: "exact-body-outcome" }));
      assert.strictEqual(actual, expected, "successful cleanup must preserve Outcome identity");
      assert.equal(child.close().outcome, "err", "the child's real ABI owner is already released");
      assert.equal(snapshot().tasks.total, 0);
    }
  }
  unwrap(await parent.closeAsync());
});

test("withScopeAsync rethrows exact synchronous values and rejected undefined after cleanup", async (t) => {
  const { runtime } = await fixture(t);
  let rendered = 0;
  const hostile = Object.freeze({ toString() { rendered += 1; throw new Error("must not render"); } });
  for (const { body, expected } of [
    { body: () => { throw hostile; }, expected: hostile },
    { body: () => Promise.reject(undefined), expected: undefined },
  ]) {
    let child;
    const result = await bounded(observe(runtime.withScopeAsync(scope => {
      child = scope;
      return body();
    })));
    assert.equal(result.kind, "threw");
    assert.strictEqual(result.error, expected);
    assert.equal(child.close().outcome, "err", "exception cleanup released the child before rejection");
  }
  const undefinedResult = await bounded(observe(runtime.withScopeAsync(() => { throw undefined; })));
  assert.equal(undefinedResult.kind, "threw");
  assert.strictEqual(undefinedResult.error, undefined);
  assert.equal(rendered, 0, "scope cleanup must never render a callback's thrown value");
});

for (const method of ["close", "closeAsync"]) {
  test(`a callback's successful ${method} preserves its exact result or exception`, async (t) => {
    let closeCalls = 0;
    const { runtime } = await fixture(t, {
      closeInterceptor() { closeCalls += 1; return undefined; },
    });
    const expected = Object.freeze({ outcome: "err", failure: {
      code: "internal_failure", recoverability: "transient", message: "original body outcome",
    } });
    const thrown = Object.freeze({ marker: "original body exception" });
    for (const bodyThrows of [false, true]) {
      const before = closeCalls;
      const result = await bounded(observe(runtime.withScopeAsync(async scope => {
        unwrap(await scope[method]());
        if (bodyThrows) throw thrown;
        return expected;
      })));
      assert.equal(result.kind, bodyThrows ? "threw" : "returned");
      assert.strictEqual(bodyThrows ? result.error : result.value, bodyThrows ? thrown : expected);
      assert.equal(closeCalls, before + 1, "a confirmed successful close must not be repeated");
    }
  });
}

for (const ancestorKind of ["scope", "runtime"]) {
  test(`a completed ancestor ${ancestorKind} close preserves a paused callback's completion`, async (t) => {
    const entered = deferred();
    const resume = deferred();
    let runtimeClosed = false;
    let closeCalls = 0;
    const { runtime } = await fixture(t, {
      beforeCleanup() { resume.resolve(); },
      runtimeAlreadyClosed: () => runtimeClosed,
      closeInterceptor() { closeCalls += 1; return undefined; },
    });
    const owner = ancestorKind === "runtime" ? runtime : unwrap(runtime.enterScope("ancestor"));
    const expected = Object.freeze(ok("paused body result"));
    const thrown = Object.freeze({ marker: "paused body exception" });
    const bracket = observe(owner.withScopeAsync(async () => {
      entered.resolve();
      await resume.promise;
      if (ancestorKind === "runtime") throw thrown;
      return expected;
    }));
    await bounded(entered.promise);
    unwrap(await bounded(owner.closeAsync()));
    runtimeClosed = ancestorKind === "runtime";
    const closesBeforeResume = closeCalls;
    resume.resolve();
    const result = await bounded(bracket);
    assert.equal(result.kind, ancestorKind === "runtime" ? "threw" : "returned");
    assert.strictEqual(ancestorKind === "runtime" ? result.error : result.value,
      ancestorKind === "runtime" ? thrown : expected);
    assert.equal(closeCalls, closesBeforeResume, "ancestor release is positive evidence that its child already closed");
  });
}

test("invalid_handle without successful SDK cleanup remains an exact visible refusal", async (t) => {
  const refusal = Object.freeze({ outcome: "err", failure: Object.freeze({
    code: "invalid_handle", recoverability: "permanent", message: "unconfirmed invalid handle",
  }) });
  let refuse = true;
  const { sdk, runtime } = await fixture(t, {
    closeInterceptor() {
      if (refuse) { refuse = false; return refusal; }
      return undefined;
    },
  });
  const expected = Object.freeze(ok("body succeeded"));
  const result = await bounded(observe(runtime.withScopeAsync(() => expected)));
  assert.equal(result.kind, "threw");
  assert.ok(result.error instanceof sdk.BrowserScopeCleanupError);
  assert.strictEqual(result.error.cleanupOutcome, refusal);
  assert.equal(result.error.bodyCompletion.kind, "returned");
  assert.strictEqual(result.error.bodyCompletion.outcome, expected);
  unwrap(await bounded(result.error.scope.closeAsync()));
});

for (const bodyThrows of [false, true]) {
  test(`withScopeAsync waits for native writes and asynchronous abort before ${bodyThrows ? "rethrowing" : "returning"}`, { timeout: 5000 }, async (t) => {
    const writing = deferred();
    const writeGate = deferred();
    const aborting = deferred();
    const abortGate = deferred();
    const { runtime, snapshot } = await fixture(t, {
      beforeCleanup() { writeGate.resolve(); abortGate.resolve(); },
    });
    const expected = Object.freeze(ok("body-finished"));
    const thrown = Object.freeze({ kind: "body-threw" });
    let readable;
    let writable;
    let pipe;
    let sourceCancelled = 0;
    let sent = false;
    let settled = false;
    const bracket = observe(runtime.withScopeAsync(async scope => {
      readable = new ReadableStream({
        pull(controller) {
          if (!sent) { sent = true; controller.enqueue(new Uint8Array([3, 1, 4])); }
        },
        cancel() { sourceCancelled += 1; },
      }, { highWaterMark: 0 });
      writable = new WritableStream({
        write(chunk) {
          assert.deepEqual([...chunk], [3, 1, 4]);
          writing.resolve();
          return writeGate.promise;
        },
        abort() { aborting.resolve(); return abortGate.promise; },
      });
      pipe = unwrap(scope.pipeTo(readable, writable));
      await writing.promise;
      if (bodyThrows) throw thrown;
      return expected;
    }));
    void bracket.then(() => { settled = true; });
    await bounded(writing.promise);
    await nextTurn();
    assert.equal(settled, false, "body completion cannot outrun the outstanding native write");
    assert.equal(readable.locked, true);
    assert.equal(writable.locked, true);
    assert.equal(snapshot().tasks.total, 1, "pending native write remains owned by the WASM ledger");
    writeGate.resolve();
    await bounded(aborting.promise);
    await nextTurn();
    assert.equal(settled, false, "body completion cannot outrun asynchronous sink cleanup");
    assert.equal(snapshot().tasks.total, 1);
    abortGate.resolve();
    const result = await bounded(bracket);
    if (bodyThrows) {
      assert.equal(result.kind, "threw");
      assert.strictEqual(result.error, thrown);
    } else {
      assert.equal(result.kind, "returned");
      assert.strictEqual(result.value, expected);
    }
    assert.equal((await bounded(pipe.closed)).outcome, "cancelled");
    assert.equal(sourceCancelled, 1);
    assert.equal(readable.locked, false);
    assert.equal(writable.locked, false);
    assert.equal(snapshot().tasks.total, 0);
    assert.equal(snapshot().tasks.cleanup_pending, 0);
  });
}

test("nested async scopes drain descendants while a sibling pipe remains owned", async (t) => {
  const { runtime, snapshot } = await fixture(t);
  const sibling = unwrap(runtime.enterScope("unrelated-sibling"));
  const siblingPipe = quietPipe(sibling);
  let childPipe;
  let nestedChild;
  const expected = Object.freeze(ok(73));
  const actual = await bounded(runtime.withScopeAsync(parent => parent.withScopeAsync(child => {
    nestedChild = child;
    childPipe = quietPipe(child);
    assert.equal(snapshot().tasks.total, 2);
    return expected;
  }, { label: "nested-child" }), { label: "nested-parent" }));
  assert.strictEqual(actual, expected);
  assert.equal(nestedChild.close().outcome, "err");
  assert.deepEqual(childPipe.counts(), { cancellations: 1, aborts: 1 });
  assert.equal(childPipe.readable.locked, false);
  assert.equal(childPipe.writable.locked, false);
  assert.deepEqual(siblingPipe.counts(), { cancellations: 0, aborts: 0 });
  assert.equal(siblingPipe.readable.locked, true);
  assert.equal(siblingPipe.writable.locked, true);
  assert.equal(snapshot().tasks.total, 1, "only the unrelated sibling pipe is still live");
  unwrap(await bounded(sibling.closeAsync()));
  assert.equal(snapshot().tasks.total, 0);
});

test("callback mutation cannot redirect the captured scope cleanup authority", async (t) => {
  const { sdk, runtime } = await fixture(t);
  const sibling = unwrap(runtime.enterScope("must-not-close"));
  let originalCore;
  let originalVersion;
  let forgedCloseCalls = 0;
  const requestedVersion = { ...sdk.abiVersion() };
  const expected = Object.freeze(ok("mutated callback view"));
  const actual = await bounded(runtime.withScopeAsync(scope => {
    originalCore = scope.core;
    originalVersion = { ...scope.consumerVersion };
    scope.core = sibling.core;
    scope.closeAsync = async () => { forgedCloseCalls += 1; return ok(undefined); };
    requestedVersion.major = 65_535;
    requestedVersion.minor = 65_535;
    return expected;
  }, { consumerVersion: requestedVersion }));
  assert.strictEqual(actual, expected);
  assert.equal(forgedCloseCalls, 0, "cleanup uses the captured trusted operation");
  const original = new sdk.RegionHandle(originalCore, originalVersion, runtime);
  assert.equal(original.close().outcome, "err", "original child was released");
  const liveChild = unwrap(sibling.enterScope("sibling-still-live"));
  unwrap(await liveChild.closeAsync());
  unwrap(await sibling.closeAsync());
});

test("native sink cleanup failure is visible and leaves an explicit retryable child", async (t) => {
  const { sdk, runtime, snapshot } = await fixture(t);
  const expected = Object.freeze(ok("body completed before cleanup"));
  let aborts = 0;
  const readable = new ReadableStream({}, { highWaterMark: 0 });
  const writable = new WritableStream({
    abort() { aborts += 1; throw new Error("native sink cannot confirm cleanup"); },
  });
  const result = await bounded(observe(runtime.withScopeAsync(scope => {
    unwrap(scope.pipeTo(readable, writable));
    return expected;
  })));
  assert.equal(result.kind, "threw");
  assert.ok(result.error instanceof sdk.BrowserScopeCleanupError);
  assert.equal(result.error.cleanupOutcome.outcome, "err");
  assert.equal(result.error.bodyCompletion.kind, "returned");
  assert.strictEqual(result.error.bodyCompletion.outcome, expected);
  assert.equal(aborts, 1);
  assert.equal(readable.locked, false);
  assert.equal(writable.locked, false);
  assert.equal(snapshot().tasks.total, 0, "native failure was published before owner refusal");
  unwrap(await bounded(result.error.scope.closeAsync()));
  assert.equal(aborts, 1, "explicit owner retry must not replay an already-settled native abort");
});

for (const completionKind of ["success", "failure", "threw"]) {
  test(`cleanup refusal preserves ${completionKind} and returns a retryable scope in a typed error`, async (t) => {
    const refusal = Object.freeze({
      outcome: "err", failure: Object.freeze({
        code: "internal_failure", recoverability: "transient", message: "injected owner-close refusal",
      }),
    });
    let refuse = true;
    let closes = 0;
    const { sdk, runtime } = await fixture(t, {
      closeInterceptor() {
        closes += 1;
        if (refuse) { refuse = false; return refusal; }
        return undefined;
      },
    });
    const bodyOutcome = Object.freeze(completionKind === "failure"
      ? { outcome: "err", failure: { code: "capability_denied", recoverability: "permanent", message: "body failure" } }
      : ok({ payload: "must remain inspectable, not serialized" }));
    const result = await bounded(observe(runtime.withScopeAsync(() => {
      if (completionKind === "threw") throw undefined;
      return bodyOutcome;
    })));
    assert.equal(result.kind, "threw", "cleanup failure must never look like body success");
    const error = result.error;
    assert.ok(error instanceof sdk.BrowserScopeCleanupError);
    assert.equal(error.code, "ASUPERSYNC_BROWSER_SCOPE_CLEANUP_FAILED");
    assert.strictEqual(error.cleanupOutcome, refusal);
    assert.ok(error.scope instanceof sdk.RegionHandle);
    if (completionKind === "threw") {
      assert.equal(error.bodyCompletion.kind, "threw");
      assert.strictEqual(error.bodyCompletion.error, undefined);
    } else {
      assert.equal(error.bodyCompletion.kind, "returned");
      assert.strictEqual(error.bodyCompletion.outcome, bodyOutcome);
    }
    for (const key of ["cleanupOutcome", "scope", "bodyCompletion"]) {
      const descriptor = Object.getOwnPropertyDescriptor(error, key);
      assert.equal(descriptor.enumerable, false, `${key} must not expose authority or body payloads in logs`);
      assert.equal(descriptor.writable, false, `${key} is a stable cleanup record`);
    }
    assert.equal(JSON.stringify(error).includes("owner_token"), false);
    assert.equal(JSON.stringify(error).includes("must remain inspectable"), false);
    assert.equal(closes, 1, "one refused attempt is not silently retried");
    unwrap(await bounded(error.scope.closeAsync()));
    assert.equal(closes, 2, "explicit retry reaches the actual ABI close");
    assert.equal(error.scope.close().outcome, "err", "retry released the retained real child");
  });
}
