/**
 * Actual SDK transaction tests; no generated WASM ABI is invoked.
 * Node 24+: node --experimental-vm-modules --test scripts/test_browser_artifact_transactions.mjs
 * Requires the test-only fake-indexeddb 6.2.5 reference implementation, either
 * an installed package or an explicit source checkout (no package build):
 *   git clone https://github.com/dumbmatter/fakeIndexedDB.git /tmp/fake-indexeddb-reference
 *   git -C /tmp/fake-indexeddb-reference checkout b92592fecd760b5e3dcc0d78528b0cf8f8e7ccce
 *   ASUPERSYNC_FAKE_INDEXEDDB_SOURCE=/tmp/fake-indexeddb-reference/src/index.ts \
 *     node --experimental-vm-modules --test scripts/test_browser_artifact_transactions.mjs
 * Missing reference dependencies fail the run; IndexedDB tests are never skipped.
 * These are not browser-engine or packaged-WASM tests.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { createRequire, stripTypeScriptTypes } from "node:module";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";

const sdkPath = process.env.ASUPERSYNC_BROWSER_SDK_SOURCE
  ?? fileURLToPath(new URL("../packages/browser/src/index.ts", import.meta.url));
const source = readFileSync(sdkPath, "utf8");
const javascript = stripTypeScriptTypes(source, { mode: "transform" });
let indexedDbSource = process.env.ASUPERSYNC_FAKE_INDEXEDDB_SOURCE;
if (!indexedDbSource) {
  try { indexedDbSource = createRequire(import.meta.url).resolve("fake-indexeddb"); }
  catch {
    throw new Error("Artifact transaction tests require fake-indexeddb 6.2.5. Set ASUPERSYNC_FAKE_INDEXEDDB_SOURCE to the pinned checkout's src/index.ts; see this script's header.");
  }
}
let packageDirectory = dirname(resolve(indexedDbSource));
let indexedDbPackage;
while (packageDirectory !== dirname(packageDirectory)) {
  const candidate = resolve(packageDirectory, "package.json");
  if (existsSync(candidate)) {
    const metadata = JSON.parse(readFileSync(candidate, "utf8"));
    if (metadata.name === "fake-indexeddb") { indexedDbPackage = metadata; break; }
  }
  packageDirectory = dirname(packageDirectory);
}
assert.equal(indexedDbPackage?.version, "6.2.5", "use the pinned fake-indexeddb reference version");
// createRequire resolves a package's CJS export. Use its ESM sibling so the
// independent implementation can share the isolated SDK host context.
if (indexedDbSource.endsWith("/build/cjs/index.js")) {
  indexedDbSource = resolve(packageDirectory, "build/esm/index.js");
}
console.log(JSON.stringify({
  scenario_id: "browser-artifact-transactions",
  sdk_source_sha256: createHash("sha256").update(source).digest("hex"),
  profiles: ["localstorage", "fake-indexeddb"],
  indexeddb_version: indexedDbPackage.version,
  indexeddb_reference_commit: "b92592fecd760b5e3dcc0d78528b0cf8f8e7ccce",
  indexeddb_source_sha256: createHash("sha256").update(readFileSync(indexedDbSource)).digest("hex"),
  no_claim: ["browser-engine execution", "Rust dispatcher", "packaged WASM", "localStorage crash atomicity"],
}));

const globals = {
  AbortController, ArrayBuffer, DataView, Uint8Array, URL, TextEncoder, TextDecoder,
  ReadableStream, WritableStream, WebAssembly, Error, TypeError, RangeError,
  DOMException, Blob, structuredClone, queueMicrotask, setTimeout, clearTimeout, setImmediate,
  window: {}, document: {}, isSecureContext: true,
  btoa: (value) => Buffer.from(value, "binary").toString("base64"),
  atob: (value) => Buffer.from(value, "base64").toString("binary"),
};
async function sdk(host) {
  const context = createContext({ ...globals, ...host });
  const modules = new Map();
  for (const [name, path, typescript] of [
    ["@asupersync/browser-core", "../packages/browser-core/index.js", false],
    ["./fetch.js", "../packages/browser/src/fetch.ts", true],
    ["@asupersync/browser-core/webtransport-streams", "../packages/browser-core/webtransport-streams.js", false],
  ]) {
    const raw = readFileSync(new URL(path, import.meta.url), "utf8");
    modules.set(name, new SourceTextModule(
      typescript ? stripTypeScriptTypes(raw, { mode: "transform" }) : raw, { context },
    ));
  }
  modules.set("./webtransport-streams.js", modules.get("@asupersync/browser-core/webtransport-streams"));
  const names = ["default", "abi_fingerprint", "abi_version", "fetch_request",
    "runtime_close", "runtime_create", "scope_close", "scope_enter", "task_cancel",
    "task_join", "task_spawn", "websocket_cancel", "websocket_close", "websocket_open",
    "websocket_recv", "websocket_send"];
  modules.set("./asupersync.js", new SyntheticModule(names, function () {
    for (const name of names) this.setExport(name, () => { throw new Error(`unexpected ABI call: ${name}`); });
  }, { context }));
  const module = new SourceTextModule(javascript, { context, identifier: sdkPath });
  await module.link((specifier) => {
    assert.ok(modules.has(specifier), `unhandled SDK import ${specifier}`);
    return modules.get(specifier);
  });
  await module.evaluate();
  return module.namespace;
}

let referenceSourceReported = false;
async function independentIndexedDb() {
  const context = createContext(globals);
  const modules = new Map();
  const sources = new Map();
  function load(path) {
    if (!modules.has(path)) {
      const source = readFileSync(path, "utf8");
      sources.set(path, source);
      modules.set(path, new SourceTextModule(
        path.endsWith(".ts")
          ? stripTypeScriptTypes(source, { mode: "transform" }) : source,
        { context, identifier: path },
      ));
    }
    return modules.get(path);
  }
  const module = load(resolve(indexedDbSource));
  await module.link((specifier, parent) => {
    assert.ok(specifier.startsWith("."), `unexpected IndexedDB dependency ${specifier}`);
    const path = resolve(dirname(parent.identifier), specifier);
    return load(existsSync(path) ? path : path.replace(/\.js$/u, ".ts"));
  });
  await module.evaluate();
  if (!referenceSourceReported) {
    const hash = createHash("sha256");
    for (const [path, raw] of [...sources].sort(([left], [right]) => left.localeCompare(right))) {
      hash.update(path.slice(packageDirectory.length));
      hash.update("\0");
      hash.update(raw);
      hash.update("\0");
    }
    console.log(JSON.stringify({ indexeddb_loaded_modules: sources.size, indexeddb_loaded_source_sha256: hash.digest("hex") }));
    referenceSourceReported = true;
  }
  return module.namespace;
}

const logicalKey = (raw) => typeof raw === "string"
  ? Buffer.from(raw.split(":").at(-1), "base64url").toString("utf8") : null;
async function environment(backend) {
  const values = new Map();
  let failDelete;
  let failSet;
  const localStorage = {
    get length() { return values.size; },
    key(index) { return [...values.keys()][index] ?? null; },
    getItem(key) { return values.get(key) ?? null; },
    setItem(key, value) {
      if (failSet?.(logicalKey(key))) { failSet = undefined; throw new DOMException("injected write failure", "QuotaExceededError"); }
      values.set(key, value);
    },
    removeItem(key) {
      if (failDelete?.(logicalKey(key))) { failDelete = undefined; throw new DOMException("injected deletion failure", "UnknownError"); }
      values.delete(key);
    },
  };
  const host = { ...globals, localStorage };
  if (backend === "indexeddb") {
    const idb = await independentIndexedDb();
    host.indexedDB = new idb.IDBFactory();
    host.IDBKeyRange = idb.IDBKeyRange;
    const originalDelete = idb.IDBObjectStore.prototype.delete;
    idb.IDBObjectStore.prototype.delete = function (key) {
      if (failDelete?.(logicalKey(key))) { failDelete = undefined; throw new DOMException("injected deletion failure", "UnknownError"); }
      return originalDelete.call(this, key);
    };
    const originalPut = idb.IDBObjectStore.prototype.put;
    idb.IDBObjectStore.prototype.put = function (value, key) {
      if (failSet?.(logicalKey(key))) { failSet = undefined; throw new DOMException("injected write failure", "QuotaExceededError"); }
      return originalPut.call(this, value, key);
    };
  }
  const api = await sdk(host);
  const store = (retention = {}, namespace = "transactions") => new api.BrowserArtifactStore({
    backend, globalObject: host, namespace, retention,
  });
  return {
    api, host, values, store,
    failDelete: (predicate) => { failDelete = predicate; },
    failSet: (predicate) => { failSet = predicate; },
  };
}

const custom = (id, value = id) => ({ kind: "custom", id, value });
const ids = (records) => Array.from(records, (record) => record.id).sort();
const bytesText = (bytes) => new TextDecoder().decode(bytes);
function artifactError(error, reason) {
  assert.equal(error.code, "ASUPERSYNC_BROWSER_ARTIFACT_OPERATION_FAILED");
  assert.equal(error.diagnostics.reason, reason);
  return true;
}
async function consistent(store) {
  const records = await store.listArtifacts();
  const archive = await store.exportArchive();
  assert.deepEqual(ids(records), ids(archive.archive.artifacts.map((entry) => entry.artifact)));
  const raw = await store.storage.listKeys(store.namespace);
  assert.equal(raw.length, records.length + (records.length ? 1 : 0), "no orphan or missing payload keys");
  for (const record of records) {
    assert.equal((await store.exportArtifact(record.id)).bytes.byteLength, record.byteLength);
  }
  return records;
}

for (const backend of ["localstorage", "indexeddb"]) {
  test(`${backend}: concurrent independent writers preserve every successful artifact and sequence`, async () => {
    const env = await environment(backend);
    const first = env.store();
    const otherApi = await sdk(env.host);
    const second = new otherApi.BrowserArtifactStore({ backend, globalObject: env.host, namespace: first.namespace });
    const requests = Array.from({ length: 12 }, (_, index) => custom(`item-${index}`, `payload-${index}`));
    const results = await Promise.all(requests.map((request, index) => (index % 2 ? first : second).persistArtifact(request)));
    assert.equal(new Set(results.map((result) => result.artifact.sequence)).size, 12);
    assert.deepEqual(ids(await consistent(first)), requests.map((request) => request.id).sort());
    for (const request of requests) assert.equal(bytesText((await second.exportArtifact(request.id)).bytes), request.value);
  });

  test(`${backend}: concurrent admission cannot exceed artifact count quota`, async () => {
    const env = await environment(backend);
    const first = env.store({ maxArtifacts: 1, quotaStrategy: "fail" });
    const second = env.store({ maxArtifacts: 1, quotaStrategy: "fail" });
    const results = await Promise.allSettled([first.persistArtifact(custom("first")), second.persistArtifact(custom("second"))]);
    assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
    const rejected = results.find((result) => result.status === "rejected");
    artifactError(rejected.reason, "quota_exceeded");
    assert.equal((await consistent(first)).length, 1);
  });

  test(`${backend}: concurrent admission cannot exceed byte quota`, async () => {
    const env = await environment(backend);
    const retention = { maxTotalBytes: 1024, maxArtifactBytes: 1024, quotaStrategy: "fail" };
    const results = await Promise.allSettled([
      env.store(retention).persistArtifact(custom("first", "a".repeat(700))),
      env.store(retention).persistArtifact(custom("second", "b".repeat(700))),
    ]);
    assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
    artifactError(results.find((result) => result.status === "rejected").reason, "quota_exceeded");
    assert.equal((await consistent(env.store(retention)))[0].byteLength, 700);
  });

  test(`${backend}: concurrent eviction retains latest committed artifacts without orphan bytes`, async () => {
    const env = await environment(backend);
    const retention = { maxArtifacts: 2, quotaStrategy: "evict_oldest" };
    const results = await Promise.all(Array.from({ length: 6 }, (_, index) =>
      env.store(retention).persistArtifact(custom(`item-${index}`))));
    const latest = results.sort((left, right) => right.artifact.sequence - left.artifact.sequence).slice(0, 2);
    assert.deepEqual(ids(await consistent(env.store(retention))), ids(latest.map((result) => result.artifact)));
  });

  test(`${backend}: delete and persist cannot resurrect a deleted index entry`, async () => {
    const env = await environment(backend);
    const first = env.store();
    const second = env.store();
    await first.persistArtifact(custom("first"));
    await first.persistArtifact(custom("second"));
    const [deleted] = await Promise.all([first.deleteArtifact("first"), second.persistArtifact(custom("third"))]);
    assert.equal(deleted, true);
    assert.deepEqual(ids(await consistent(first)), ["second", "third"]);
  });

  test(`${backend}: archive reads one consistent snapshot during deletion`, async () => {
    const env = await environment(backend);
    const first = env.store();
    await first.persistArtifact(custom("first"));
    await first.persistArtifact(custom("second"));
    const [exported] = await Promise.all([first.exportArchive(), env.store().deleteArtifact("first")]);
    const archivedIds = ids(exported.archive.artifacts.map((entry) => entry.artifact));
    assert.ok(JSON.stringify(archivedIds) === '["first","second"]' || JSON.stringify(archivedIds) === '["second"]');
    for (const entry of exported.archive.artifacts) {
      assert.equal(Buffer.from(entry.payloadBase64, "base64").toString(), entry.artifact.id);
    }
    assert.deepEqual(ids(await consistent(first)), ["second"]);
  });

  test(`${backend}: concurrent namespace clears count each artifact once`, async () => {
    const env = await environment(backend);
    const first = env.store();
    await first.persistArtifact(custom("first"));
    await first.persistArtifact(custom("second"));
    const counts = await Promise.all([first.clearArtifacts(), env.store().clearArtifacts()]);
    assert.deepEqual(counts.sort(), [0, 2]);
    assert.deepEqual(ids(await consistent(first)), []);
  });

  test(`${backend}: persist snapshots bytes before waiting for admission`, async () => {
    const env = await environment(backend);
    const store = env.store();
    const bytes = Uint8Array.of(1, 2, 3);
    const pending = store.persistArtifact(custom("snapshot", bytes));
    bytes.fill(9);
    await pending;
    assert.deepEqual(Array.from((await store.exportArtifact("snapshot")).bytes), [1, 2, 3]);
  });

  test(`${backend}: failed index publication restores original artifact and quota`, async () => {
    const env = await environment(backend);
    const store = env.store({ maxArtifacts: 1 });
    await store.persistArtifact(custom("original", "old payload"));
    env.failSet((key) => key === "__artifact_index__");
    await assert.rejects(store.persistArtifact(custom("replacement")), (error) => artifactError(error, "quota_exceeded"));
    assert.deepEqual(ids(await consistent(store)), ["original"]);
    assert.equal(bytesText((await store.exportArtifact("original")).bytes), "old payload");
    await store.persistArtifact(custom("recovered"));
    assert.deepEqual(ids(await consistent(store)), ["recovered"]);
  });

  test(`${backend}: failed eviction rolls back the entire replacement`, async () => {
    const env = await environment(backend);
    const store = env.store({ maxArtifacts: 1 });
    await store.persistArtifact(custom("original"));
    const originalPayload = (await store.storage.listKeys(store.namespace)).find((key) => key.startsWith("artifact:"));
    env.failDelete((key) => key === originalPayload);
    await assert.rejects(store.persistArtifact(custom("replacement")), (error) => artifactError(error, "storage_failed"));
    assert.deepEqual(ids(await consistent(store)), ["original"]);
    assert.equal(bytesText((await store.exportArtifact("original")).bytes), "original");
  });

  test(`${backend}: failed payload deletion retains its live index entry`, async () => {
    const env = await environment(backend);
    const store = env.store();
    await store.persistArtifact(custom("original"));
    const originalPayload = (await store.storage.listKeys(store.namespace)).find((key) => key.startsWith("artifact:"));
    env.failDelete((key) => key === originalPayload);
    await assert.rejects(store.deleteArtifact("original"), (error) => artifactError(error, "storage_failed"));
    assert.deepEqual(ids(await consistent(store)), ["original"]);
    assert.equal(await store.deleteArtifact("original"), true);
    assert.deepEqual(ids(await consistent(store)), []);
  });

  test(`${backend}: corrupt counters and payload aliases fail before mutation`, async () => {
    const env = await environment(backend);
    const store = env.store();
    await store.persistArtifact(custom("original"));
    const raw = await store.storage.get(store.namespace, "__artifact_index__");
    for (const mutate of [
      (index) => { index.nextSequence = Number.MAX_SAFE_INTEGER; },
      (index) => { index.entries[0].byteLength = -1; },
      (index) => { index.entries[0].payloadKey = "__artifact_index__"; },
      (index) => { index.entries.push({ ...index.entries[0] }); },
    ]) {
      const index = JSON.parse(bytesText(raw));
      mutate(index);
      const corrupt = new TextEncoder().encode(JSON.stringify(index));
      await store.storage.set(store.namespace, "__artifact_index__", corrupt);
      await assert.rejects(store.persistArtifact(custom("replacement")), (error) => artifactError(error, "corrupt_index"));
      assert.deepEqual(Array.from(await store.storage.get(store.namespace, "__artifact_index__")), Array.from(corrupt));
      assert.equal((await store.storage.listKeys(store.namespace)).length, 2);
    }
    await store.storage.set(store.namespace, "__artifact_index__", raw);
    assert.deepEqual(ids(await consistent(store)), ["original"]);
  });

  test(`${backend}: corrupt-index recovery clears only its namespace`, async () => {
    const env = await environment(backend);
    const store = env.store();
    const other = env.store({}, "other");
    await store.persistArtifact(custom("original"));
    await other.persistArtifact(custom("untouched"));
    await store.storage.set(store.namespace, "__artifact_index__", new TextEncoder().encode("not json"));
    assert.equal(await store.clearArtifacts(), 1);
    assert.deepEqual(ids(await consistent(store)), []);
    assert.deepEqual(ids(await consistent(other)), ["untouched"]);
  });
}

test("localstorage: independent SDK realms share the origin lock and snapshot request bytes", async () => {
  const env = await environment("localstorage");
  const requests = [];
  let release;
  let queue = new Promise((resolve) => { release = resolve; });
  env.host.navigator = { locks: { request(name, options, callback) {
    requests.push({ name, mode: options.mode });
    const result = queue.then(callback);
    queue = result.catch(() => undefined);
    return result;
  } } };
  const otherApi = await sdk(env.host);
  const first = env.store();
  const second = new otherApi.BrowserArtifactStore({ backend: "localstorage", globalObject: env.host, namespace: first.namespace });
  const bytes = Uint8Array.of(1, 2);
  const one = first.persistArtifact(custom("first", bytes));
  const two = second.persistArtifact(custom("second"));
  assert.equal(env.values.size, 0, "host storage must wait for granted origin lock");
  assert.equal(requests.length, 2);
  assert.equal(requests[0].name, requests[1].name);
  assert.deepEqual(requests.map((request) => request.mode), ["exclusive", "exclusive"]);
  bytes.fill(9);
  release();
  await Promise.all([one, two]);
  assert.deepEqual(ids(await consistent(first)), ["first", "second"]);
  assert.deepEqual(Array.from((await first.exportArtifact("first")).bytes), [1, 2]);
  assert.ok(requests.some((request) => request.mode === "shared"));
});
