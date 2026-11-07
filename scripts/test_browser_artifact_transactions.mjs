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
  let failGet;
  let failDelete;
  let failSet;
  let mutationObserver;
  let storageQuota = Infinity;
  const localStorage = {
    get length() { return values.size; },
    key(index) { return [...values.keys()][index] ?? null; },
    getItem(key) {
      if (failGet?.(logicalKey(key))) { failGet = undefined; throw new DOMException("injected read failure", "UnknownError"); }
      return values.get(key) ?? null;
    },
    setItem(key, value) {
      if (failSet?.(logicalKey(key))) { failSet = undefined; throw new DOMException("injected write failure", "QuotaExceededError"); }
      const projected = [...values].reduce((total, [raw, stored]) =>
        total + (raw === key ? 0 : raw.length + stored.length), key.length + value.length);
      if (projected > storageQuota) throw new DOMException("storage quota exceeded", "QuotaExceededError");
      values.set(key, value);
      mutationObserver?.({ operation: "set", key: logicalKey(key), values: new Map(values) });
    },
    removeItem(key) {
      if (failDelete?.(logicalKey(key))) { failDelete = undefined; throw new DOMException("injected deletion failure", "UnknownError"); }
      values.delete(key);
      mutationObserver?.({ operation: "delete", key: logicalKey(key), values: new Map(values) });
    },
  };
  const host = { ...globals, localStorage };
  if (backend === "indexeddb") {
    const idb = await independentIndexedDb();
    host.indexedDB = new idb.IDBFactory();
    host.IDBKeyRange = idb.IDBKeyRange;
    const originalGet = idb.IDBObjectStore.prototype.get;
    idb.IDBObjectStore.prototype.get = function (key) {
      if (failGet?.(logicalKey(key))) { failGet = undefined; throw new DOMException("injected read failure", "UnknownError"); }
      return originalGet.call(this, key);
    };
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
    failGet: (predicate) => { failGet = predicate; },
    failDelete: (predicate) => { failDelete = predicate; },
    failSet: (predicate) => { failSet = predicate; },
    observeMutations: (observer) => { mutationObserver = observer; },
    setStorageQuota: (quota) => { storageQuota = quota; },
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

async function corruptStoredValue(env, store, logical = "__artifact_index__") {
  if (store.storage.backend === "localstorage") {
    const rawKey = [...env.values.keys()].find((key) => logicalKey(key) === logical &&
      Buffer.from(key.split(":").at(-2), "base64url").toString("utf8") === store.namespace);
    assert.ok(rawKey, "the value must already be persisted");
    // Use the real host decoder: Buffer.from is deliberately more permissive
    // than the browser atob boundary for invalid Base64.
    env.host.atob = atob;
    env.values.set(rawKey, "invalid base64 %");
    return;
  }
  const database = await new Promise((resolve, reject) => {
    const request = env.host.indexedDB.open(store.storage.dbName, store.storage.version);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  try {
    await new Promise((resolve, reject) => {
      const transaction = database.transaction(store.storage.storeName, "readwrite");
      const objectStore = transaction.objectStore(store.storage.storeName);
      transaction.oncomplete = resolve;
      transaction.onabort = () => reject(transaction.error);
      const request = objectStore.getAllKeys();
      request.onsuccess = () => {
        const rawKey = request.result.find((key) => logicalKey(key) === logical &&
          Buffer.from(key.split(":").at(-2), "base64url").toString("utf8") === store.namespace);
        assert.ok(rawKey, "the value must already be persisted");
        // A foreign client can store structured-cloneable non-byte values.
        objectStore.put({ invalid: "not a BrowserStorage byte value" }, rawKey);
      };
    });
  } finally { database.close(); }
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

  test(`${backend}: corrupt stored index bytes cannot wedge explicit recovery`, async () => {
    const env = await environment(backend);
    const store = env.store();
    const other = env.store({}, "other");
    await store.persistArtifact(custom("original"));
    await other.persistArtifact(custom("untouched"));
    await corruptStoredValue(env, store);
    assert.equal(await store.clearArtifacts(), 1);
    assert.deepEqual(ids(await consistent(store)), []);
    assert.deepEqual(ids(await consistent(other)), ["untouched"]);
    await store.persistArtifact(custom("recovered"));
    assert.equal(bytesText((await store.exportArtifact("recovered")).bytes), "recovered");
  });

  test(`${backend}: corrupt stored index bytes report recovery-capable diagnostics`, async () => {
    const env = await environment(backend);
    const store = env.store();
    await store.persistArtifact(custom("original"));
    await corruptStoredValue(env, store);
    for (const operation of [
      () => store.listArtifacts(),
      () => store.exportArchive(),
      () => store.persistArtifact(custom("replacement")),
      () => store.deleteArtifact("original"),
    ]) {
      await assert.rejects(operation(), (error) => artifactError(error, "corrupt_index"));
    }
    assert.equal((await store.storage.listKeys(store.namespace)).length, 2,
      "observing corruption must not silently discard persisted artifacts");
  });

  test(`${backend}: failed index I/O cannot trigger destructive corruption recovery`, async () => {
    const env = await environment(backend);
    const store = env.store();
    await store.persistArtifact(custom("original"));
    env.failGet((key) => key === "__artifact_index__");
    await assert.rejects(store.clearArtifacts(), (error) => artifactError(error, "storage_failed"));
    assert.deepEqual(ids(await consistent(store)), ["original"]);
    assert.equal(bytesText((await store.exportArtifact("original")).bytes), "original");
  });

  test(`${backend}: truncated and oversized payloads cannot export as complete artifacts`, async () => {
    const env = await environment(backend);
    const store = env.store();
    await store.persistArtifact(custom("original", "original payload"));
    await store.persistArtifact(custom("untouched"));
    const index = JSON.parse(bytesText(await store.storage.get(store.namespace, "__artifact_index__")));
    const entry = index.entries.find((item) => item.id === "original");
    const original = await store.storage.get(store.namespace, entry.payloadKey);
    for (const damaged of [new Uint8Array(), original.slice(0, -1), new Uint8Array(original.length + 1)]) {
      await store.storage.set(store.namespace, entry.payloadKey, damaged);
      await assert.rejects(store.exportArtifact("original"), (error) => artifactError(error, "corrupt_index"));
      await assert.rejects(store.exportArchive(), (error) => artifactError(error, "corrupt_index"));
      assert.equal(bytesText((await store.exportArtifact("untouched")).bytes), "untouched");
      assert.deepEqual(Array.from(await store.storage.get(store.namespace, entry.payloadKey)), Array.from(damaged),
        "export failures must leave the damaged bytes available for explicit recovery");
      assert.deepEqual(ids(await store.listArtifacts()), ["original", "untouched"]);
    }
    await store.storage.set(store.namespace, entry.payloadKey, original);
    assert.deepEqual(ids(await consistent(store)), ["original", "untouched"]);
  });

  test(`${backend}: undecodable payloads report corruption without discarding valid artifacts`, async () => {
    const env = await environment(backend);
    const store = env.store();
    await store.persistArtifact(custom("original"));
    await store.persistArtifact(custom("untouched"));
    const index = JSON.parse(bytesText(await store.storage.get(store.namespace, "__artifact_index__")));
    const entry = index.entries.find((item) => item.id === "original");
    await corruptStoredValue(env, store, entry.payloadKey);
    await assert.rejects(store.exportArtifact("original"), (error) => artifactError(error, "corrupt_index"));
    await assert.rejects(store.exportArchive(), (error) => artifactError(error, "corrupt_index"));
    assert.equal(bytesText((await store.exportArtifact("untouched")).bytes), "untouched");
    assert.equal((await store.storage.listKeys(store.namespace)).length, 3);
    assert.equal(await store.deleteArtifact("original"), true);
    assert.deepEqual(ids(await consistent(store)), ["untouched"]);
    await store.persistArtifact(custom("original", "recovered"));
    assert.equal(bytesText((await store.exportArtifact("original")).bytes), "recovered");
  });

  test(`${backend}: payload read I/O failures remain retryable storage failures`, async () => {
    const env = await environment(backend);
    const store = env.store();
    await store.persistArtifact(custom("original"));
    for (const operation of [() => store.exportArtifact("original"), () => store.exportArchive()]) {
      env.failGet((key) => key?.startsWith("artifact:"));
      await assert.rejects(operation(), (error) => artifactError(error, "storage_failed"));
      assert.deepEqual(ids(await consistent(store)), ["original"]);
    }
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


// A captured state models interruption immediately after one successful host
// mutation: restart from it without executing the original operation's rollback.
// This proves reference consistency, not multi-key atomicity or browser fsync.
async function exportableAtEveryMutation(env, operation, retainedIds = []) {
  const snapshots = [];
  env.observeMutations(snapshot => {
    if (snapshot.key === "__artifact_index__" || snapshot.key?.startsWith("artifact:")) snapshots.push(snapshot);
  });
  try { await operation(); }
  finally { env.observeMutations(undefined); }
  assert.ok(snapshots.length > 0, "the operation must reach a storage mutation");
  for (const [offset, snapshot] of snapshots.entries()) {
    const restarted = await environment("localstorage");
    for (const [key, value] of snapshot.values) restarted.values.set(key, value);
    let archive;
    try { archive = await restarted.store().exportArchive(); }
    catch (error) {
      assert.fail(`interruption after mutation ${offset + 1} (${snapshot.operation} ${snapshot.key}) left unreadable artifacts: ${error.message}`);
    }
    const visible = ids(archive.archive.artifacts.map(entry => entry.artifact));
    for (const id of retainedIds) {
      assert.ok(visible.includes(id), `retained artifact ${id} vanished after mutation ${offset + 1}`);
    }
    for (const entry of archive.archive.artifacts) {
      assert.equal(Buffer.from(entry.payloadBase64, "base64").byteLength, entry.artifact.byteLength,
        "every published record must name its complete payload");
    }
  }
  return snapshots;
}

test("localstorage: interrupted same-id replacement never publishes a missing payload", async () => {
  const env = await environment("localstorage");
  const store = env.store();
  await store.persistArtifact(custom("anchor", "keep"));
  await store.persistArtifact(custom("target", "before"));
  const snapshots = await exportableAtEveryMutation(env,
    () => store.persistArtifact(custom("target", "after")), ["anchor"]);
  assert.equal(bytesText((await store.exportArtifact("target")).bytes), "after");
  assert.deepEqual(ids(await consistent(store)), ["anchor", "target"]);
  assert.ok(snapshots.some(snapshot => snapshot.operation === "delete" && snapshot.key.startsWith("artifact:")),
    "the old payload must actually be reclaimed");
});

test("localstorage: interrupted multi-entry eviction preserves the retained artifacts", async () => {
  const env = await environment("localstorage");
  const store = env.store();
  await store.persistArtifact(custom("old-a"));
  await store.persistArtifact(custom("old-b"));
  await store.persistArtifact(custom("anchor"));
  const bounded = env.store({ maxArtifacts: 2 });
  await exportableAtEveryMutation(env,
    () => bounded.persistArtifact(custom("replacement")), ["anchor"]);
  assert.deepEqual(ids(await consistent(bounded)), ["anchor", "replacement"]);
});

test("localstorage: an empty reclamation index remains readable and reserves the new sequence", async () => {
  const env = await environment("localstorage");
  const store = env.store({ maxArtifacts: 1 });
  await store.persistArtifact(custom("original"));
  const snapshots = await exportableAtEveryMutation(env,
    () => store.persistArtifact(custom("replacement")));
  const staged = snapshots.find(snapshot => {
    const raw = [...snapshot.values].find(([key]) => logicalKey(key) === "__artifact_index__")?.[1];
    return raw && JSON.parse(Buffer.from(raw, "base64").toString("utf8")).entries.length === 0;
  });
  assert.ok(staged, "replacement must publish an empty retained set before reclamation");
  const restarted = await environment("localstorage");
  for (const [key, value] of staged.values) restarted.values.set(key, value);
  const recovered = await restarted.store().persistArtifact(custom("after-interruption"));
  assert.equal(recovered.artifact.sequence, 3, "do not reuse the interrupted replacement's sequence");
  assert.deepEqual(ids(await consistent(store)), ["replacement"]);
});

for (const last of [false, true]) {
  test(`localstorage: interrupted deletion keeps every remaining payload readable (last=${last})`, async () => {
    const env = await environment("localstorage");
    const store = env.store();
    if (!last) await store.persistArtifact(custom("anchor"));
    await store.persistArtifact(custom("target"));
    await exportableAtEveryMutation(env,
      async () => assert.equal(await store.deleteArtifact("target"), true), last ? [] : ["anchor"]);
    assert.deepEqual(ids(await consistent(store)), last ? [] : ["anchor"]);
  });
}

test("localstorage: interrupted namespace clear unpublishes its index before payload removal", async () => {
  const env = await environment("localstorage");
  const store = env.store();
  await store.persistArtifact(custom("first"));
  await store.persistArtifact(custom("second"));
  await env.store({}, "other").persistArtifact(custom("unrelated"));
  const snapshots = await exportableAtEveryMutation(env,
    async () => assert.equal(await store.clearArtifacts(), 2));
  assert.deepEqual(ids(await consistent(store)), []);
  for (const snapshot of snapshots) {
    const restarted = await environment("localstorage");
    for (const [key, value] of snapshot.values) restarted.values.set(key, value);
    assert.deepEqual(ids(await consistent(restarted.store({}, "other"))), ["unrelated"]);
  }
});

test("localstorage: replacement still succeeds without room for old plus new payloads", async () => {
  const env = await environment("localstorage");
  const store = env.store();
  await store.persistArtifact(custom("anchor", "keep"));
  await store.persistArtifact(custom("slot", "a".repeat(4096)));
  const quota = [...env.values].reduce((total, [key, value]) => total + key.length + value.length, 0);
  env.setStorageQuota(quota);
  const snapshots = await exportableAtEveryMutation(env,
    () => store.persistArtifact(custom("slot", "b".repeat(4096))), ["anchor"]);
  for (const snapshot of snapshots) {
    assert.ok([...snapshot.values].reduce((total, [key, value]) => total + key.length + value.length, 0) <= quota);
  }
  assert.equal(bytesText((await store.exportArtifact("slot")).bytes), "b".repeat(4096));
  assert.deepEqual(ids(await consistent(store)), ["anchor", "slot"]);
});

test("localstorage: interrupted rollback of final-index failure preserves readable original artifacts", async () => {
  const env = await environment("localstorage");
  const store = env.store();
  await store.persistArtifact(custom("anchor"));
  await store.persistArtifact(custom("target", "original"));
  let publications = 0;
  env.failSet(key => key === "__artifact_index__" && ++publications === 2);
  await exportableAtEveryMutation(env, () => assert.rejects(
    store.persistArtifact(custom("target", "replacement")),
    error => artifactError(error, "quota_exceeded")), ["anchor"]);
  assert.equal(bytesText((await store.exportArtifact("target")).bytes), "original");
  assert.deepEqual(ids(await consistent(store)), ["anchor", "target"]);
});

test("localstorage: interrupted rollback of payload-write failure preserves retained references", async () => {
  const env = await environment("localstorage");
  const store = env.store();
  await store.persistArtifact(custom("anchor"));
  await store.persistArtifact(custom("target", "original"));
  env.failSet(key => key?.startsWith("artifact:"));
  await exportableAtEveryMutation(env, () => assert.rejects(
    store.persistArtifact(custom("target", "replacement")),
    error => artifactError(error, "quota_exceeded")), ["anchor"]);
  assert.equal(bytesText((await store.exportArtifact("target")).bytes), "original");
  assert.deepEqual(ids(await consistent(store)), ["anchor", "target"]);
});

test("localstorage: failed rollback unpublication cannot remove any more payloads", async () => {
  const env = await environment("localstorage");
  const store = env.store();
  await store.persistArtifact(custom("anchor"));
  await store.persistArtifact(custom("target", "original"));
  let replacementFailed = false;
  env.failSet(key => {
    if (!key?.startsWith("artifact:")) return false;
    replacementFailed = true;
    return true;
  });
  // Rollback must restore its retained-only publication before deleting any
  // payload. Refuse that write after the first failure has been consumed.
  const set = env.host.localStorage.setItem;
  let blocked = false;
  env.host.localStorage.setItem = function (key, value) {
    if (replacementFailed && logicalKey(key) === "__artifact_index__" && !blocked) {
      blocked = true;
      throw new DOMException("rollback publication refused", "QuotaExceededError");
    }
    return set.call(this, key, value);
  };
  const snapshots = await exportableAtEveryMutation(env, () => assert.rejects(
    store.persistArtifact(custom("target", "replacement")),
    error => artifactError(error, "storage_failed")), ["anchor"]);
  assert.equal(blocked, true);
  assert.equal(snapshots.length, 2,
    "only the staged index and original-payload removal may precede the refused rollback publication");
  assert.equal(snapshots.at(-1).key.startsWith("artifact:"), true,
    "no mutation may follow a refused rollback publication");
  assert.deepEqual(ids(await store.listArtifacts()), ["anchor"]);
});

test("localstorage: failed original-payload restoration leaves only readable retained entries", async () => {
  const env = await environment("localstorage");
  const store = env.store();
  await store.persistArtifact(custom("anchor"));
  await store.persistArtifact(custom("target", "original"));
  const index = JSON.parse(bytesText(await store.storage.get(store.namespace, "__artifact_index__")));
  const originalPayloadKey = index.entries.find(entry => entry.id === "target").payloadKey;
  let publications = 0;
  let finalPublicationFailed = false;
  env.failSet(key => {
    if (key !== "__artifact_index__" || ++publications !== 2) return false;
    finalPublicationFailed = true;
    return true;
  });
  const set = env.host.localStorage.setItem;
  let restorationRefused = false;
  env.host.localStorage.setItem = function (key, value) {
    if (finalPublicationFailed && logicalKey(key) === originalPayloadKey) {
      restorationRefused = true;
      throw new DOMException("original payload restoration refused", "QuotaExceededError");
    }
    return set.call(this, key, value);
  };
  const snapshots = await exportableAtEveryMutation(env, () => assert.rejects(
    store.persistArtifact(custom("target", "replacement")),
    error => artifactError(error, "storage_failed")), ["anchor"]);
  assert.equal(finalPublicationFailed, true, "fail only after writing the replacement payload");
  assert.equal(restorationRefused, true, "exercise failure while restoring the old payload");
  assert.ok(snapshots.some(snapshot => snapshot.operation === "set" && snapshot.key.startsWith("artifact:")),
    "the replacement payload must be written before publication fails");
  assert.deepEqual(ids(await consistent(store)), ["anchor"]);
});
