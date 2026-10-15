// Run with Node 24+ and its native Web Storage implementation; no dependencies
// or browser/backend substitutes are required:
// node --experimental-transform-types --experimental-webstorage \
//   --localstorage-file=/tmp/asupersync-storage-recovery.sqlite \
//   tests/fixtures/vite-vanilla-consumer/scripts/check-storage-recovery.mjs
import assert from "node:assert/strict";
import { registerHooks } from "node:module";
import test from "node:test";
import { pathToFileURL } from "node:url";

const repository = new URL("../../../../", import.meta.url);
const browserCore = new URL("packages/browser-core/index.js", repository).href;
registerHooks({
  resolve(specifier, context, nextResolve) {
    return specifier === "@asupersync/browser-core"
      ? { url: browserCore, shortCircuit: true }
      : nextResolve(specifier, context);
  },
});

// An optional preserved source snapshot makes old-code failure reproducible.
const browserSource = process.env.ASUPERSYNC_BROWSER_SOURCE
  ? pathToFileURL(process.env.ASUPERSYNC_BROWSER_SOURCE).href
  : new URL("packages/browser/src/index.ts", repository).href;
const { BrowserStorage, BrowserArtifactStore, BrowserServiceWorkerBrokerStore } =
  await import(browserSource);
const nativeStorage = globalThis.localStorage;
assert.equal(nativeStorage.constructor.name, "Storage", "native Web Storage is required");

// These descriptors select the public APIs' host boundary. All storage,
// encoding, and persistence operations use the real Node implementations.
const browserGlobals = {
  window: globalThis,
  document: {},
  WebAssembly,
  TextEncoder,
  TextDecoder,
  btoa,
  atob,
  localStorage: nativeStorage,
};
const options = { backend: "localstorage", globalObject: browserGlobals };
const storage = new BrowserStorage(options);
const encoded = (value) => Buffer.from(value, "utf8").toString("base64url");
const prefixFor = (namespace) => `asupersync:storage:v1:${encoded(namespace)}:`;
const rawKeys = (namespace) => {
  const prefix = prefixFor(namespace);
  return Array.from({ length: nativeStorage.length }, (_, index) => nativeStorage.key(index))
    .filter((key) => key !== null && key.startsWith(prefix));
};
const clearFixture = (namespace) => {
  for (const key of rawKeys(namespace)) nativeStorage.removeItem(key);
};
const malformedSuffixes = ["", "_w", "YQ==", "YR", "%", "IA", "IHg", "\uffffx"];

test("localStorage listing skips corrupt and noncanonical keys without aliases", async (t) => {
  const namespace = "storage-recovery-list";
  clearFixture(namespace);
  t.after(() => clearFixture(namespace));
  const expected = ["a", "sentinel", "\ufffd", "\ud83d\ude00"].sort();
  for (const key of expected) await storage.set(namespace, key, [42]);
  for (const suffix of malformedSuffixes) {
    nativeStorage.setItem(`${prefixFor(namespace)}${suffix}`, "AQ");
  }
  assert.deepEqual(await storage.listKeys(namespace), expected);
  assert.equal(rawKeys(namespace).length, expected.length + malformedSuffixes.length);
  assert.deepEqual(await storage.get(namespace, "\ufffd"), new Uint8Array([42]));
});

test("localStorage clear removes exact malformed raw keys and preserves other namespaces", async (t) => {
  const namespace = "storage-recovery-clear";
  const otherNamespace = `${namespace}-other`;
  const boundaryKey = `${prefixFor(namespace).slice(0, -1)};`;
  clearFixture(namespace);
  clearFixture(otherNamespace);
  t.after(() => {
    clearFixture(namespace);
    clearFixture(otherNamespace);
    nativeStorage.removeItem(boundaryKey);
  });
  await storage.set(namespace, "a", [1]);
  await storage.set(otherNamespace, "sentinel", [99]);
  nativeStorage.setItem(boundaryKey, "outside");
  for (const suffix of ["", "_w", "YQ==", "YR", "IA", "IHg"]) {
    nativeStorage.setItem(`${prefixFor(namespace)}${suffix}`, "not base64");
  }
  const count = rawKeys(namespace).length;
  assert.equal(await storage.clearNamespace(namespace), count);
  assert.deepEqual(rawKeys(namespace), []);
  assert.equal(await storage.clearNamespace(namespace), 0);
  assert.deepEqual(await storage.get(otherNamespace, "sentinel"), new Uint8Array([99]));
  assert.equal(nativeStorage.getItem(boundaryKey), "outside");
});

test("invalid Base64 keys cannot block localStorage namespace recovery", async (t) => {
  const namespace = "storage-recovery-invalid-base64";
  clearFixture(namespace);
  t.after(() => clearFixture(namespace));
  nativeStorage.setItem(`${prefixFor(namespace)}%`, "invalid");
  assert.equal(await storage.clearNamespace(namespace), 1);
  assert.deepEqual(rawKeys(namespace), []);
});

test("same-turn localStorage clears count each raw record once", async (t) => {
  const namespace = "storage-recovery-concurrent";
  clearFixture(namespace);
  t.after(() => clearFixture(namespace));
  for (const key of ["a", "b", "c"]) await storage.set(namespace, key, [1]);
  const peer = new BrowserStorage(options);
  assert.deepEqual(
    await Promise.all([storage.clearNamespace(namespace), peer.clearNamespace(namespace)]),
    [3, 0],
  );
  assert.deepEqual(rawKeys(namespace), []);
});

test("artifact recovery clears a corrupt index and malformed raw keys, then accepts new artifacts", async (t) => {
  const namespace = "storage-recovery-artifacts";
  clearFixture(namespace);
  t.after(() => clearFixture(namespace));
  const artifacts = new BrowserArtifactStore({ ...options, namespace });
  await artifacts.persistArtifact({ id: "old", kind: "custom", value: new Uint8Array([1]) });
  await storage.set(namespace, "__artifact_index__", new TextEncoder().encode("{broken"));
  for (const suffix of malformedSuffixes) {
    nativeStorage.setItem(`${prefixFor(namespace)}${suffix}`, "invalid");
  }
  await assert.rejects(
    artifacts.listArtifacts(),
    (error) => error.diagnostics?.reason === "corrupt_index",
  );
  assert.equal(await artifacts.clearArtifacts(), 1);
  assert.deepEqual(rawKeys(namespace), []);
  assert.deepEqual(await artifacts.listArtifacts(), []);
  await artifacts.persistArtifact({ id: "new", kind: "custom", value: new Uint8Array([7, 8]) });
  assert.deepEqual((await artifacts.exportArtifact("new")).bytes, new Uint8Array([7, 8]));
});

test("broker localStorage listing and reset tolerate malformed raw records", async (t) => {
  const namespace = "storage-recovery-broker";
  clearFixture(namespace);
  t.after(() => clearFixture(namespace));
  const broker = new BrowserServiceWorkerBrokerStore({
    ...options,
    namespace,
    globalObject: {
      ...browserGlobals,
      skipWaiting: Promise.resolve.bind(Promise),
      clients: {},
      registration: { scope: "https://fixture.invalid/" },
    },
  });
  for (const suffix of malformedSuffixes) {
    nativeStorage.setItem(`${prefixFor(namespace)}${suffix}`, "invalid");
  }
  assert.deepEqual(await broker.listPendingWork(), []);
  assert.equal(await broker.clearBrokerState(), malformedSuffixes.length);
  assert.deepEqual(rawKeys(namespace), []);
  assert.equal(await broker.clearBrokerState(), 0);
});
