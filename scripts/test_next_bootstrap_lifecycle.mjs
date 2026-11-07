/**
 * Next bootstrap ownership regressions (Node 24+):
 * node --unhandled-rejections=strict --experimental-vm-modules --test \
 *   --test-concurrency=1 scripts/test_next_bootstrap_lifecycle.mjs
 *
 * Executes the complete Next adapter source with intentional browser-support,
 * bootstrap and handle doubles. Deferred bootstrap results expose real adapter
 * races without timers; handle ledgers detect lost owners and duplicate close.
 * This is JS adapter evidence, not Next rendering, browser or WASM execution.
 * ASUPERSYNC_NEXT_SOURCE selects an unmodified older source for negative controls.
 * No source file is rewritten by this harness.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";

const sourcePath = process.env.ASUPERSYNC_NEXT_SOURCE
  ?? fileURLToPath(new URL("../packages/next/src/index.ts", import.meta.url));
const source = readFileSync(sourcePath, "utf8");
const javaScript = stripTypeScriptTypes(source, { mode: "transform" });
console.log(JSON.stringify({
  scenario_id: "next-bootstrap-generation-ownership",
  source_sha256: createHash("sha256").update(source).digest("hex"),
  evidence_scope: "complete Next adapter, intentional browser bootstrap and handle doubles",
  no_claim: ["Next rendering", "browser integration", "WASM execution"],
}));

const Outcome = {
  ok: (value) => ({ outcome: "ok", value }),
  err: (message) => ({ outcome: "err", failure: {
    code: "internal_failure", recoverability: "unknown", message,
  } }),
  cancelled: (cancellation) => ({ outcome: "cancelled", cancellation }),
};
const formatOutcomeFailure = (outcome) => outcome.failure?.message
  ?? outcome.cancellation?.message ?? outcome.message ?? outcome.outcome;

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

function cancelled(outcome) {
  assert.equal(outcome.outcome, "cancelled", JSON.stringify(outcome));
  assert.equal(outcome.cancellation.kind, "next_bootstrap_invalidated");
  assert.equal(outcome.cancellation.phase, "completed");
  assert.equal(outcome.cancellation.origin_region, "next-client-bootstrap");
  return outcome.cancellation;
}

async function fixture(options = {}, hooks = {}) {
  const requests = [];
  const context = createContext({});
  const browser = new SyntheticModule([
    "Outcome", "formatOutcomeFailure", "detectBrowserRuntimeSupport", "createBrowserRuntime",
  ], function () {
    this.setExport("Outcome", Outcome);
    this.setExport("formatOutcomeFailure", formatOutcomeFailure);
    this.setExport("detectBrowserRuntimeSupport", (globalObject) => {
      hooks.support?.(globalObject);
      return {
        supported: true, packageName: "@asupersync/browser", reason: "supported",
        supportClass: "supported", message: "intentional supported-browser double",
        guidance: [], capabilities: {},
      };
    });
    this.setExport("createBrowserRuntime", (runtimeOptions) => {
      const request = { ...deferred(), options: runtimeOptions, index: requests.length };
      requests.push(request);
      hooks.create?.(request);
      return request.promise;
    });
  }, { context, identifier: "intentional-browser-bootstrap-double" });
  const next = new SourceTextModule(javaScript, { context, identifier: sourcePath });
  await next.link((specifier) => {
    assert.equal(specifier, "@asupersync/browser");
    return browser;
  });
  await next.evaluate();
  const adapter = new next.namespace.NextClientBootstrapAdapter(options);

  function finish(index, behavior = {}) {
    const record = {
      scopeEnters: 0, scopeCloses: 0, runtimeCloses: 0, closeOrder: [],
      scopeCloseVersions: [], runtimeCloseVersions: [],
    };
    const consumerVersion = requests[index].options.consumerVersion ?? null;
    const scope = {
      consumerVersion,
      close(version) {
        record.scopeCloses += 1;
        record.scopeCloseVersions.push(version);
        record.closeOrder.push("scope");
        behavior.scopeClose?.(version);
        return Outcome.ok(undefined);
      },
    };
    const runtime = {
      consumerVersion,
      enterScope(label, version) {
        record.scopeEnters += 1;
        record.label = label;
        record.consumerVersion = version;
        behavior.enter?.();
        return behavior.enterOutcome ?? Outcome.ok(scope);
      },
      close(version) {
        record.runtimeCloses += 1;
        record.runtimeCloseVersions.push(version);
        record.closeOrder.push("runtime");
        behavior.runtimeClose?.(version);
        return Outcome.ok(undefined);
      },
    };
    Object.assign(record, { runtime, scope });
    requests[index].resolve(Outcome.ok(runtime));
    return record;
  }

  function hydrate() {
    adapter.beginHydration();
    adapter.completeHydration();
  }
  return { adapter, requests, finish, hydrate };
}

test("concurrent initialization shares one runtime, scope and result", async () => {
  const f = await fixture();
  f.hydrate();
  const first = f.adapter.initializeRuntime();
  const second = f.adapter.initializeRuntime();
  const ensured = f.adapter.ensureRuntimeReady();
  assert.equal(f.requests.length, 1, "only one runtime allocation may be in flight");
  const owner = f.finish(0);
  const outcomes = await Promise.all([first, second, ensured]);
  for (const outcome of outcomes) assert.equal(ok(outcome), owner.scope);
  assert.equal(outcomes[0], outcomes[1]);
  assert.equal(owner.scopeEnters, 1);
  assert.equal(f.adapter.snapshot().runtimeInitAttempts, 1);
  assert.equal(f.adapter.snapshot().runtimeInitSuccesses, 1);
  assert.equal(f.adapter.snapshot().activeScopeGeneration, 1);
  assert.equal(ok(await f.adapter.initializeRuntime()), owner.scope);
  assert.equal(f.requests.length, 1);
  const event = f.adapter.close();
  assert.equal(event.action, "close_runtime", "close remains synchronous");
  assert.deepEqual(owner.closeOrder, ["scope", "runtime"]);
  assert.equal(f.adapter.currentRuntime(), null);
  assert.equal(f.adapter.currentScope(), null);
});

test("bootstrap forwards the complete runtime options including fetch authority", async () => {
  const options = {
    wasmInput: {}, consumerVersion: { major: 1, minor: 0 }, eagerInit: false,
    globalObject: {}, preferredLane: "browser_main_thread", healthPolicy: {},
    healthScopeKey: "next-app", now: () => 42, fetchAuthority: { grant: "explicit" },
    label: "client-route",
  };
  const f = await fixture(options);
  f.hydrate();
  const pending = f.adapter.initializeRuntime();
  for (const name of [
    "wasmInput", "consumerVersion", "eagerInit", "globalObject", "preferredLane",
    "healthPolicy", "healthScopeKey", "now", "fetchAuthority",
  ]) {
    assert.equal(f.requests[0].options[name], options[name], `${name} must reach browser bootstrap`);
  }
  const owner = f.finish(0);
  ok(await pending);
  assert.equal(owner.label, options.label);
  assert.equal(owner.consumerVersion, options.consumerVersion);
  f.adapter.close();
});

const invalidations = [
  ["cancel", (adapter) => adapter.cancelBootstrap("route cancelled")],
  ["hydration mismatch", (adapter) => adapter.hydrationMismatch("different markup")],
  ["explicit initialization failure", (adapter) => adapter.runtimeInitFailed("bootstrap refused")],
  ["close", (adapter) => adapter.close("unmount")],
  ["retry recovery", (adapter) => adapter.recover("retry_runtime_init")],
  ["hydration recovery", (adapter) => adapter.recover("reset_to_hydrating")],
  ["hard navigation", (adapter) => adapter.navigate("hard_navigation", "/other")],
  ["pending popstate", (adapter) => adapter.navigate("popstate", "/previous")],
  ["hot reload", (adapter) => adapter.hotReload()],
  ["cache revalidation", (adapter) => adapter.cacheRevalidated()],
];

for (const [name, invalidate] of invalidations) {
  test(`${name} fences a pending bootstrap and disposes its late runtime`, async () => {
    const f = await fixture();
    f.hydrate();
    const pending = f.adapter.initializeRuntime();
    invalidate(f.adapter);
    const expected = f.adapter.snapshot();
    const stale = f.finish(0);
    cancelled(await pending);
    assert.equal(stale.scopeEnters, 0, "a stale runtime must not enter a scope");
    assert.equal(stale.runtimeCloses, 1);
    assert.equal(f.adapter.currentRuntime(), null);
    assert.equal(f.adapter.currentScope(), null);
    assert.deepEqual(f.adapter.snapshot(), expected, "late completion must not change lifecycle state");
  });
}

test("soft navigation and no-op recovery preserve the pending attempt", async () => {
  const f = await fixture();
  f.hydrate();
  const first = f.adapter.initializeRuntime();
  f.adapter.navigate("soft_navigation", "/next");
  f.adapter.recover("none");
  const second = f.adapter.initializeRuntime();
  assert.equal(f.requests.length, 1);
  const owner = f.finish(0);
  assert.equal(ok(await first), owner.scope);
  assert.equal(ok(await second), owner.scope);
  f.adapter.navigate("popstate", "/previous");
  assert.equal(f.adapter.currentRuntime(), owner.runtime);
  assert.equal(f.adapter.snapshot().phase, "runtime_ready");
  f.adapter.close();
});

test("old completion cannot clear a replacement's pending single flight", async () => {
  const f = await fixture();
  f.hydrate();
  const old = f.adapter.initializeRuntime();
  f.adapter.close();
  const current = f.adapter.initializeRuntime();
  const stale = f.finish(0);
  cancelled(await old);
  const joined = f.adapter.initializeRuntime();
  assert.equal(f.requests.length, 2, "joining replacement must not allocate a third runtime");
  const owner = f.finish(1);
  assert.equal(ok(await current), owner.scope);
  assert.equal(ok(await joined), owner.scope);
  assert.equal(stale.runtimeCloses, 1);
  assert.equal(owner.runtimeCloses, 0);
  f.adapter.close();
});

for (const completion of ["success", "failure", "rejection"]) {
  test(`old ${completion} cannot change or close a ready replacement`, async () => {
    const f = await fixture();
    f.hydrate();
    const old = f.adapter.initializeRuntime();
    f.adapter.cancelBootstrap("retry in another generation");
    f.adapter.recover("retry_runtime_init");
    const current = f.adapter.initializeRuntime();
    const owner = f.finish(1);
    assert.equal(ok(await current), owner.scope);
    const expected = f.adapter.snapshot();
    let stale;
    if (completion === "success") stale = f.finish(0);
    else if (completion === "failure") f.requests[0].resolve(Outcome.err("old refusal"));
    else f.requests[0].reject(new Error("old factory rejection"));
    cancelled(await old);
    assert.deepEqual(f.adapter.snapshot(), expected);
    assert.equal(f.adapter.currentRuntime(), owner.runtime);
    assert.equal(f.adapter.currentScope(), owner.scope);
    assert.equal(owner.scopeCloses, 0);
    assert.equal(owner.runtimeCloses, 0);
    if (stale) {
      assert.equal(stale.runtimeCloses, 1);
      assert.equal(stale.scopeEnters, 0);
    }
    f.adapter.close();
  });
}

test("a live factory rejection is shared and a later retry can allocate", async () => {
  const f = await fixture();
  f.hydrate();
  const first = f.adapter.initializeRuntime();
  const second = f.adapter.initializeRuntime();
  const error = new Error("factory unavailable");
  const observed = Promise.allSettled([first, second]);
  f.requests[0].reject(error);
  for (const result of await observed) {
    assert.equal(result.status, "rejected");
    assert.equal(result.reason, error);
  }
  const retry = f.adapter.initializeRuntime();
  assert.equal(f.requests.length, 2);
  const owner = f.finish(1);
  assert.equal(ok(await retry), owner.scope);
  f.adapter.close();
});

for (const mode of ["refusal", "throw"]) {
  test(`scope admission ${mode} releases the unpublished runtime`, async () => {
    const f = await fixture();
    f.hydrate();
    const pending = f.adapter.initializeRuntime();
    const error = new Error("scope admission failed");
    const owner = f.finish(0, mode === "refusal"
      ? { enterOutcome: Outcome.err(error.message) }
      : { enter: () => { throw error; } });
    if (mode === "refusal") assert.equal((await pending).outcome, "err");
    else await assert.rejects(pending, (cause) => cause === error);
    assert.equal(owner.runtimeCloses, 1);
    assert.equal(owner.scopeCloses, 0);
    assert.equal(f.adapter.currentRuntime(), null);
    assert.equal(f.adapter.currentScope(), null);
  });
}

for (const reentry of ["support", "options", "factory"]) {
  test(`synchronous ${reentry} reentry joins the published attempt`, async () => {
    let f;
    let joined;
    let entered = false;
    const reenter = () => {
      if (!entered) {
        entered = true;
        joined = f.adapter.initializeRuntime();
      }
    };
    const options = reentry === "options"
      ? { get fetchAuthority() { reenter(); return undefined; } }
      : {};
    const hooks = reentry === "support" ? { support: reenter }
      : reentry === "factory" ? { create: reenter } : {};
    f = await fixture(options, hooks);
    f.hydrate();
    const first = f.adapter.initializeRuntime();
    assert.equal(entered, true);
    assert.equal(f.requests.length, 1);
    const owner = f.finish(0);
    assert.equal(ok(await first), owner.scope);
    assert.equal(ok(await joined), owner.scope);
    f.adapter.close();
  });
}

test("cancellation from an option getter prevents factory dispatch", async () => {
  let f;
  f = await fixture({
    get fetchAuthority() {
      f.adapter.cancelBootstrap("authority owner unmounted");
      return undefined;
    },
  });
  f.hydrate();
  cancelled(await f.adapter.initializeRuntime());
  assert.equal(f.requests.length, 0);
});

test("factory reentry can retire its attempt and start a replacement", async () => {
  let f;
  let replacement;
  f = await fixture({}, {
    create(request) {
      if (request.index === 0) {
        f.adapter.close();
        replacement = f.adapter.initializeRuntime();
      }
    },
  });
  f.hydrate();
  const first = f.adapter.initializeRuntime();
  assert.equal(f.requests.length, 2);
  const stale = f.finish(0);
  cancelled(await first);
  const owner = f.finish(1);
  assert.equal(ok(await replacement), owner.scope);
  assert.equal(stale.runtimeCloses, 1);
  f.adapter.close();
});

test("cancellation during scope admission retires both unpublished handles", async () => {
  const f = await fixture();
  f.hydrate();
  let replacement;
  const first = f.adapter.initializeRuntime();
  const stale = f.finish(0, {
    enter() {
      f.adapter.close();
      replacement = f.adapter.initializeRuntime();
    },
  });
  cancelled(await first);
  assert.deepEqual(stale.closeOrder, ["scope", "runtime"]);
  assert.equal(f.requests.length, 2);
  const owner = f.finish(1);
  assert.equal(ok(await replacement), owner.scope);
  f.adapter.close();
});

test("an initialization log hook can close, recover and initialize a fresh owner", async () => {
  let f;
  let replacement;
  let replaced = false;
  f = await fixture({
    onLogEvent(event) {
      if (event.action === "initialize_runtime" && !replaced) {
        replaced = true;
        f.adapter.close();
        f.adapter.recover("retry_runtime_init");
        replacement = f.adapter.initializeRuntime();
        throw new Error("obsolete observer failed after starting replacement");
      }
    },
  });
  f.hydrate();
  const first = f.adapter.initializeRuntime();
  const stale = f.finish(0);
  cancelled(await first);
  assert.deepEqual(stale.closeOrder, ["scope", "runtime"]);
  assert.equal(f.requests.length, 2);
  const joined = f.adapter.initializeRuntime();
  assert.equal(f.requests.length, 2);
  const owner = f.finish(1);
  assert.equal(ok(await replacement), owner.scope);
  assert.equal(ok(await joined), owner.scope);
  assert.equal(owner.runtimeCloses, 0);
  f.adapter.close();
});

test("a log-hook microtask can invalidate before the shared result is delivered", async () => {
  let f;
  f = await fixture({
    onLogEvent(event) {
      if (event.action === "initialize_runtime") queueMicrotask(() => f.adapter.close());
    },
  });
  f.hydrate();
  const pending = f.adapter.initializeRuntime();
  const owner = f.finish(0);
  cancelled(await pending);
  assert.deepEqual(owner.closeOrder, ["scope", "runtime"]);
  assert.equal(f.adapter.currentScope(), null);
});

test("a throwing live log hook leaves its published owner reachable for cleanup", async () => {
  const error = new Error("observer failed");
  const f = await fixture({
    onLogEvent(event) {
      if (event.action === "initialize_runtime") throw error;
    },
  });
  f.hydrate();
  const pending = f.adapter.initializeRuntime();
  const owner = f.finish(0);
  await assert.rejects(pending, (cause) => cause === error);
  assert.equal(f.adapter.currentRuntime(), owner.runtime);
  assert.equal(f.adapter.currentScope(), owner.scope);
  assert.equal(ok(await f.adapter.initializeRuntime()), owner.scope);
  assert.equal(f.requests.length, 1);
  f.adapter.close();
  assert.deepEqual(owner.closeOrder, ["scope", "runtime"]);
});

test("cleanup detaches both old handles before callbacks and still closes the runtime on throw", async () => {
  const f = await fixture();
  f.hydrate();
  const first = f.adapter.initializeRuntime();
  let replacement;
  const old = f.finish(0, {
    scopeClose() {
      assert.equal(f.adapter.currentScope(), null);
      assert.equal(f.adapter.currentRuntime(), null);
      replacement = f.adapter.initializeRuntime();
      throw new Error("scope close callback failed");
    },
  });
  ok(await first);
  const event = f.adapter.close();
  assert.match(event.detail, /scope close callback failed/);
  assert.equal(old.runtimeCloses, 1);
  assert.equal(f.requests.length, 2);
  const owner = f.finish(1);
  assert.equal(ok(await replacement), owner.scope);
  assert.equal(f.adapter.currentRuntime(), owner.runtime);
  f.adapter.close();
  assert.deepEqual(owner.closeOrder, ["scope", "runtime"]);
});

test("unprintable scope-close exceptions cannot prevent independent runtime cleanup", async () => {
  const f = await fixture();
  f.hydrate();
  const pending = f.adapter.initializeRuntime();
  const hostile = { toString() { throw new Error("cannot stringify"); } };
  const owner = f.finish(0, { scopeClose() { throw hostile; } });
  ok(await pending);
  const event = f.adapter.close();
  assert.match(event.detail, /cleanup threw an unprintable value/);
  assert.deepEqual(owner.closeOrder, ["scope", "runtime"]);
  assert.equal(f.adapter.currentRuntime(), null);
});

for (const stale of [false, true]) {
  test(`${stale ? "stale" : "live"} owner uses its captured version after options change`, async () => {
    const version = { major: 1, minor: 0 };
    let expired = false;
    const f = await fixture({
      get consumerVersion() {
        if (expired) throw new Error("options no longer owned");
        return version;
      },
    });
    f.hydrate();
    const pending = f.adapter.initializeRuntime();
    if (stale) f.adapter.close();
    expired = true;
    const owner = f.finish(0);
    if (stale) {
      cancelled(await pending);
      assert.equal(owner.scopeEnters, 0);
    } else {
      ok(await pending);
      assert.equal(owner.consumerVersion, version);
      f.adapter.close();
      assert.deepEqual(owner.scopeCloseVersions, [version]);
    }
    assert.deepEqual(owner.runtimeCloseVersions, [version]);
  });
}

test("hydration, cache refresh, hard navigation and hot reload retain the phase API", async () => {
  const f = await fixture();
  await assert.rejects(f.adapter.initializeRuntime(), /requires a hydrated client boundary/);
  assert.equal(f.requests.length, 0);
  const first = f.adapter.hydrateAndInitialize();
  const initial = f.finish(0);
  assert.equal(ok(await first), initial.scope);
  f.adapter.cacheRevalidated();
  assert.equal(f.adapter.snapshot().phase, "hydrated");
  assert.deepEqual(initial.closeOrder, ["scope", "runtime"]);
  const second = f.adapter.ensureRuntimeReady();
  const refreshed = f.finish(1);
  ok(await second);
  f.adapter.navigate("hard_navigation", "/new-route");
  assert.equal(f.adapter.snapshot().phase, "server_rendered");
  assert.deepEqual(refreshed.closeOrder, ["scope", "runtime"]);
  const third = f.adapter.ensureRuntimeReady();
  const navigated = f.finish(2);
  ok(await third);
  f.adapter.hotReload();
  assert.equal(f.adapter.snapshot().phase, "hydrating");
  assert.deepEqual(navigated.closeOrder, ["scope", "runtime"]);
  const fourth = f.adapter.ensureRuntimeReady();
  const reloaded = f.finish(3);
  assert.equal(ok(await fourth), reloaded.scope);
  assert.equal(f.adapter.snapshot().runtimeInitAttempts, 4);
  assert.equal(f.adapter.snapshot().runtimeInitSuccesses, 4);
  assert.equal(f.adapter.snapshot().activeScopeGeneration, 4);
  assert.equal(f.adapter.snapshot().scopeInvalidationCount, 3);
  f.adapter.close();
});
