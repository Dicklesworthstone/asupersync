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
import { createContext, runInNewContext, SourceTextModule, SyntheticModule } from "node:vm";

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
  let readObserver;
  let abortPut;
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
      const request = originalGet.call(this, key);
      request.addEventListener("success", () => readObserver?.(logicalKey(key)));
      return request;
    };
    const originalDelete = idb.IDBObjectStore.prototype.delete;
    idb.IDBObjectStore.prototype.delete = function (key) {
      if (failDelete?.(logicalKey(key))) { failDelete = undefined; throw new DOMException("injected deletion failure", "UnknownError"); }
      return originalDelete.call(this, key);
    };
    const originalPut = idb.IDBObjectStore.prototype.put;
    idb.IDBObjectStore.prototype.put = function (value, key) {
      if (failSet?.(logicalKey(key))) { failSet = undefined; throw new DOMException("injected write failure", "QuotaExceededError"); }
      const request = originalPut.call(this, value, key);
      if (abortPut?.(logicalKey(key))) {
        abortPut = undefined;
        request.addEventListener("success", () => this.transaction.abort());
      }
      return request;
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
    observeReads: (observer) => { readObserver = observer; },
    abortAfterPut: (predicate) => { abortPut = predicate; },
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

  test(`${backend}: exported archives restore binary, JSON, and text into a fresh namespace`, async () => {
    const env = await environment(backend);
    const source = env.store({}, "capture");
    await source.persistArtifact({ kind: "custom", id: "binary", value: new Uint8Array([0, 255, 128]), filename: "frame.bin", tags: ["raw"] });
    await source.persistTraceRecord({ seed: 37, events: ["cancel", "drained"] }, { id: "trace" });
    await source.persistArtifact({ kind: "evidence", id: "text", value: "recovered \u{1f30d}", filename: "evidence.txt" });
    const exported = await source.exportArchive();
    const foreignBuffer = runInNewContext("new Uint8Array(bytes).buffer", { bytes: Array.from(exported.bytes) });
    assert.equal(foreignBuffer instanceof ArrayBuffer, false, "exercise a separate realm's buffer brand");
    for (const [name, value] of [["object", exported.archive], ["bytes", exported.bytes], ["text", bytesText(exported.bytes)], ["buffer", exported.bytes.buffer], ["foreign-buffer", foreignBuffer]]) {
      const target = env.store({}, `restored-${name}`);
      const result = await target.importArchive(value);
      assert.deepEqual(ids(result.artifacts), ["binary", "text", "trace"]);
      assert.deepEqual(Array.from(result.evictedArtifactIds), []);
      assert.equal(result.totalArtifacts, 3);
      assert.equal(result.totalBytes, exported.archive.artifacts.reduce((sum, entry) => sum + entry.artifact.byteLength, 0));
      const restored = await target.exportArchive();
      assert.deepEqual(JSON.parse(JSON.stringify(restored.archive.artifacts)), JSON.parse(JSON.stringify(exported.archive.artifacts)));
      assert.equal(restored.archive.namespace, `restored-${name}`);
      await consistent(target);
    }
    await consistent(source);
  });

  test(`${backend}: archive conflicts require an explicit replacement and rebase imported sequences`, async () => {
    const env = await environment(backend);
    const source = env.store({}, "capture");
    await source.persistArtifact(custom("older", "older imported bytes"));
    await source.persistArtifact(custom("same", "replacement"));
    const archive = (await source.exportArchive()).archive;
    const target = env.store();
    await target.persistArtifact(custom("same", "original"));
    await target.persistArtifact(custom("untouched"));
    await assert.rejects(target.importArchive(archive), (error) => artifactError(error, "artifact_conflict"));
    assert.equal(bytesText((await target.exportArtifact("same")).bytes), "original");
    const result = await target.importArchive(archive, { conflict: "replace" });
    assert.deepEqual(Array.from(result.artifacts, (entry) => [entry.id, entry.sequence]), [["same", 4], ["older", 3]]);
    assert.equal(bytesText((await target.exportArtifact("same")).bytes), "replacement");
    assert.deepEqual(ids(await consistent(target)), ["older", "same", "untouched"]);
  });

  test(`${backend}: archive admission honors destination quotas without discarding imported entries`, async () => {
    const env = await environment(backend);
    const source = env.store({ maxArtifacts: 5 }, "capture");
    await source.persistArtifact(custom("first"));
    await source.persistArtifact(custom("second"));
    const archive = (await source.exportArchive()).archive;
    const target = env.store({ maxArtifacts: 2 });
    await target.persistArtifact(custom("oldest"));
    await target.persistArtifact(custom("latest"));
    const result = await target.importArchive(archive);
    assert.deepEqual(Array.from(result.evictedArtifactIds), ["oldest", "latest"]);
    assert.deepEqual(ids(await consistent(target)), ["first", "second"]);
    const tooSmall = env.store({ maxArtifacts: 1 }, "too-small");
    await tooSmall.persistArtifact(custom("kept"));
    await assert.rejects(tooSmall.importArchive(archive), (error) => artifactError(error, "quota_exceeded"));
    assert.deepEqual(ids(await consistent(tooSmall)), ["kept"]);
    const fail = env.store({ maxArtifacts: 2, quotaStrategy: "fail" }, "fail-quota");
    await fail.persistArtifact(custom("kept"));
    await assert.rejects(fail.importArchive(archive), (error) => artifactError(error, "quota_exceeded"));
    assert.deepEqual(ids(await consistent(fail)), ["kept"]);
  });

  test(`${backend}: malformed archive entries fail before any storage mutation`, async () => {
    const env = await environment(backend);
    const source = env.store({}, "capture");
    await source.persistArtifact(custom("one"));
    await source.persistArtifact(custom("two"));
    const exported = (await source.exportArchive()).archive;
    const target = env.store();
    await target.persistArtifact(custom("kept"));
    const cases = [
      (archive) => { archive.schemaVersion = 2; },
      (archive) => { archive.artifacts[1].payloadBase64 = "%"; },
      (archive) => { archive.artifacts[1].payloadBase64 = "b25l="; },
      (archive) => { archive.artifacts[1].artifact.byteLength += 1; },
      (archive) => { archive.artifacts[1].artifact.id = archive.artifacts[0].artifact.id; },
      (archive) => { archive.artifacts[1].artifact.sequence = archive.artifacts[0].artifact.sequence; },
      (archive) => { archive.artifacts[1].artifact.tags = [null]; },
      (archive) => { archive.artifacts[1].artifact.kind = "unknown"; },
    ];
    for (const mutate of cases) {
      const archive = JSON.parse(JSON.stringify(exported));
      mutate(archive);
      await assert.rejects(target.importArchive(archive), (error) => artifactError(error, "invalid_archive"));
      assert.deepEqual(ids(await consistent(target)), ["kept"]);
    }
    await assert.rejects(target.importArchive("{bad-json"), (error) => artifactError(error, "invalid_archive"));
    assert.deepEqual(ids(await consistent(target)), ["kept"]);
  });

  test(`${backend}: archive payload limits are checked against the destination before decoding`, async () => {
    const env = await environment(backend);
    const source = env.store({}, "capture");
    await source.persistArtifact(custom("large", "x".repeat(300)));
    const archive = (await source.exportArchive()).archive;
    const target = env.store({ maxArtifactBytes: 256 });
    await target.persistArtifact(custom("kept"));
    await assert.rejects(target.importArchive(archive), (error) => artifactError(error, "payload_too_large"));
    assert.deepEqual(ids(await consistent(target)), ["kept"]);
  });

  test(`${backend}: sparse object archives cannot publish missing records or tags`, async () => {
    const env = await environment(backend);
    const source = env.store({}, "capture");
    await source.persistArtifact(custom("new"));
    const exported = (await source.exportArchive()).archive;
    const target = env.store();
    await target.persistArtifact(custom("kept"));
    for (const mutate of [
      (archive) => { archive.artifacts.length += 1; },
      (archive) => { archive.artifacts[0].artifact.tags = new Array(1); },
    ]) {
      const archive = JSON.parse(JSON.stringify(exported));
      mutate(archive);
      await assert.rejects(target.importArchive(archive), (error) => artifactError(error, "invalid_archive"));
      assert.deepEqual(ids(await consistent(target)), ["kept"]);
    }
  });

  test(`${backend}: aggregate archive bytes cannot raise destination limits through source metadata`, async () => {
    const env = await environment(backend);
    const source = env.store({}, "capture");
    await source.persistArtifact(custom("first", "x".repeat(600)));
    await source.persistArtifact(custom("second", "y".repeat(600)));
    const archive = (await source.exportArchive()).archive;
    const target = env.store({ maxArtifactBytes: 1024, maxTotalBytes: 1024 });
    await target.persistArtifact(custom("kept"));
    await assert.rejects(target.importArchive(archive), (error) => artifactError(error, "quota_exceeded"));
    assert.deepEqual(ids(await consistent(target)), ["kept"]);
    assert.equal(target.retentionPolicy().maxTotalBytes, 1024);
  });

  test(`${backend}: empty archives are a no-op and exhausted sequences reject complete imports`, async () => {
    const env = await environment(backend);
    const source = env.store({}, "capture");
    const empty = (await source.exportArchive()).archive;
    const target = env.store();
    await target.persistArtifact(custom("kept"));
    const before = await target.storage.get(target.namespace, "__artifact_index__");
    const result = await target.importArchive(empty);
    assert.equal(result.artifacts.length, 0);
    assert.equal(result.totalArtifacts, 1);
    assert.deepEqual(await target.storage.get(target.namespace, "__artifact_index__"), before);
    await source.persistArtifact(custom("new"));
    const index = JSON.parse(bytesText(before));
    index.nextSequence = Number.MAX_SAFE_INTEGER;
    await target.storage.set(target.namespace, "__artifact_index__", new TextEncoder().encode(JSON.stringify(index)));
    await assert.rejects(target.importArchive((await source.exportArchive()).archive), (error) => artifactError(error, "corrupt_index"));
    assert.deepEqual(ids(await consistent(target)), ["kept"]);
  });

  test(`${backend}: a failed multi-artifact import rolls back replacement and eviction together`, async () => {
    const env = await environment(backend);
    const source = env.store({}, "capture");
    await source.persistArtifact(custom("same", "replacement"));
    await source.persistArtifact(custom("new", "new payload"));
    const archive = (await source.exportArchive()).archive;
    const target = env.store({ maxArtifacts: 2 });
    await target.persistArtifact(custom("old", "retained on failure"));
    await target.persistArtifact(custom("same", "original"));
    let payloadWrites = 0;
    env.failSet((key) => key?.startsWith("artifact:") && ++payloadWrites === 2);
    await assert.rejects(target.importArchive(archive, { conflict: "replace" }), (error) => artifactError(error, "quota_exceeded"));
    assert.deepEqual(ids(await consistent(target)), ["old", "same"]);
    assert.equal(bytesText((await target.exportArtifact("same")).bytes), "original");
    const result = await target.importArchive(archive, { conflict: "replace" });
    assert.deepEqual(ids(result.artifacts), ["new", "same"]);
    assert.deepEqual(ids(await consistent(target)), ["new", "same"]);
  });

  test(`${backend}: concurrent archive and single-artifact admission share one sequence and quota frontier`, async () => {
    const env = await environment(backend);
    const source = env.store({}, "capture");
    await source.persistArtifact(custom("one"));
    await source.persistArtifact(custom("two"));
    const archive = (await source.exportArchive()).archive;
    const target = env.store({ maxArtifacts: 2, quotaStrategy: "fail" });
    const results = await Promise.allSettled([target.importArchive(archive), env.store({ maxArtifacts: 2, quotaStrategy: "fail" }).persistArtifact(custom("other"))]);
    assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
    artifactError(results.find((result) => result.status === "rejected").reason, "quota_exceeded");
    const records = await consistent(target);
    assert.ok(JSON.stringify(ids(records)) === '["one","two"]' || JSON.stringify(ids(records)) === '["other"]');
    assert.equal(new Set(records.map((record) => record.sequence)).size, records.length);
  });
}

test("localstorage: archive input is owned before waiting for the cross-tab lock", async () => {
  const env = await environment("localstorage");
  const source = env.store({}, "capture");
  await source.persistArtifact({ ...custom("original", "accepted bytes"), tags: ["accepted"] });
  const archive = (await source.exportArchive()).archive;
  let release;
  const lock = new Promise((resolve) => { release = resolve; });
  env.host.navigator = { locks: { request: (_name, _options, callback) => lock.then(callback) } };
  const target = env.store();
  const pending = target.importArchive(archive);
  archive.artifacts[0].artifact.id = "mutated";
  archive.artifacts[0].artifact.tags.push("mutated");
  archive.artifacts[0].payloadBase64 = "bXV0YXRlZA";
  archive.artifacts.length = 0;
  release();
  const result = await pending;
  assert.deepEqual(ids(result.artifacts), ["original"]);
  assert.deepEqual(Array.from(result.artifacts[0].tags), ["accepted"]);
  assert.equal(bytesText((await target.exportArtifact("original")).bytes), "accepted bytes");
  await consistent(target);
});

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

const brokerRegistration = (overrides = {}) => ({
  admission: {
    origin: "https://broker.example.test",
    registrationScope: "https://broker.example.test/app/",
    appNamespace: "broker-transactions",
    appVersionMajor: 1,
    brokerProtocolVersion: 1,
    runProfile: "restartable",
  },
  capabilityManifestVersion: "caps-v1",
  lifecycleState: "brokering",
  ...overrides,
});
const brokerWork = (overrides = {}) => ({
  artifactNamespace: "broker-evidence",
  brokerWorkId: "work-1",
  capabilityManifestVersion: "caps-v1",
  idempotencyKey: "event-1",
  leaseEpoch: 1,
  metadata: { progress: "accepted" },
  sourceEventKind: "fetch",
  ...overrides,
});
const brokerRecord = value => JSON.parse(JSON.stringify(value));
function brokerError(error, reason) {
  assert.equal(error.code, "ASUPERSYNC_BROWSER_SERVICE_WORKER_BROKER_OPERATION_FAILED");
  assert.equal(error.diagnostics.reason, reason);
  return true;
}
async function brokerEnvironment(backend) {
  const env = await environment(backend);
  const host = {
    ...env.host,
    window: undefined,
    document: undefined,
    clients: { claim: async () => undefined, matchAll: async () => [] },
    location: { origin: "https://broker.example.test" },
    registration: { scope: "https://broker.example.test/app/" },
    skipWaiting: async () => undefined,
  };
  const broker = (options = {}) => new env.api.BrowserServiceWorkerBrokerStore({
    backend, globalObject: host, namespace: "broker-transactions", now: () => 1_000,
    ...options,
  });
  const first = broker();
  await first.registerBroker(brokerRegistration());
  return { ...env, brokerHost: host, broker, first };
}

for (const backend of ["indexeddb", "localstorage"]) {
  test(`${backend}: broker rejects stale work without replacing newer durable progress`, async () => {
    const { first, broker } = await brokerEnvironment(backend);
    await first.persistBrokerWork(brokerWork({ leaseEpoch: 2, metadata: { progress: "new owner" } }));
    await assert.rejects(broker().persistBrokerWork(brokerWork()),
      error => brokerError(error, "broker_restart_reconciliation_failed"));
    const pending = await broker().listPendingWork();
    assert.equal(pending.length, 1);
    assert.equal(pending[0].leaseEpoch, 2);
    assert.equal(pending[0].metadata.progress, "new owner");
  });

  test(`${backend}: broker work and handoff share one monotonic lease fence`, async () => {
    const { first, broker } = await brokerEnvironment(backend);
    await first.persistDurableHandoff(brokerWork({ leaseEpoch: 3 }));
    await assert.rejects(broker().persistBrokerWork(brokerWork({ leaseEpoch: 2 })),
      error => brokerError(error, "broker_restart_reconciliation_failed"));
    await first.persistBrokerWork(brokerWork({ leaseEpoch: 4 }));
    await assert.rejects(broker().persistDurableHandoff(brokerWork({ leaseEpoch: 3 })),
      error => brokerError(error, "broker_restart_reconciliation_failed"));
    assert.equal((await first.listPendingWork())[0].leaseEpoch, 4);
    assert.equal((await first.listDurableHandoffs())[0].leaseEpoch, 3);
  });

  test(`${backend}: broker refuses work and handoff from a foreign capability manifest`, async () => {
    const { first } = await brokerEnvironment(backend);
    for (const operation of ["persistBrokerWork", "persistDurableHandoff"]) {
      await assert.rejects(first[operation](brokerWork({ capabilityManifestVersion: "caps-other" })),
        error => brokerError(error, "capability_manifest_mismatch_on_restart"));
    }
    assert.equal((await first.listPendingWork()).length, 0);
    assert.equal((await first.listDurableHandoffs()).length, 0);
  });

  test(`${backend}: broker re-registration cannot adopt another app's retained work`, async () => {
    const { first, broker } = await brokerEnvironment(backend);
    await first.persistBrokerWork(brokerWork());
    const registration = brokerRegistration();
    registration.admission.appNamespace = "another-app";
    await assert.rejects(broker().registerBroker(registration),
      error => brokerError(error, "app_namespace_mismatch"));
    assert.equal((await first.readRegistration()).admission.appNamespace, "broker-transactions");
    assert.equal((await first.listPendingWork())[0].idempotencyKey, "event-1");
  });

  test(`${backend}: broker same-epoch replay preserves receipts and the retained handoff workflow`, async () => {
    const env = await brokerEnvironment(backend);
    let now = 2_000;
    const store = env.broker({ now: () => ++now });
    await store.setLifecycleState("reconciling_durable_state");
    const descriptor = await store.persistBrokerWork(brokerWork());
    env.failSet(key => key === "broker_work:work-1");
    assert.deepEqual(brokerRecord(await store.persistBrokerWork(brokerWork())), brokerRecord(descriptor));
    env.failSet(undefined);
    await store.setLifecycleState("brokering");
    const request = brokerWork({ metadata: { destination: "worker" } });
    const handoff = await store.persistDurableHandoff(request);
    env.failSet(key => key === "broker_handoff:work-1");
    assert.deepEqual(brokerRecord(await store.persistDurableHandoff(request)), brokerRecord(handoff));
    env.failSet(undefined);
    await store.setLifecycleState("draining");
    await store.setLifecycleState("quiescent");
    const restarted = env.broker();
    assert.equal((await restarted.readRegistration()).lifecycleState, "quiescent");
    assert.deepEqual(brokerRecord((await restarted.listPendingWork())[0]), brokerRecord(descriptor));
    assert.deepEqual(brokerRecord((await restarted.listDurableHandoffs())[0]), brokerRecord(handoff));
    assert.equal(await restarted.clearBrokerState(), 3);
    assert.equal(await restarted.readRegistration(), null);
    assert.equal((await restarted.listPendingWork()).length, 0);
    assert.equal((await restarted.listDurableHandoffs()).length, 0);
  });

  test(`${backend}: broker same-epoch conflicts cannot replace an admitted event identity`, async () => {
    const { first } = await brokerEnvironment(backend);
    const descriptor = await first.persistBrokerWork(brokerWork());
    const handoff = await first.persistDurableHandoff(brokerWork());
    for (const operation of ["persistBrokerWork", "persistDurableHandoff"]) {
      for (const change of [
        { idempotencyKey: "different-event" },
        { artifactNamespace: "other-evidence" },
        { sourceEventKind: "push" },
      ]) {
        await assert.rejects(first[operation](brokerWork(change)),
          error => brokerError(error, "broker_restart_reconciliation_failed"));
      }
    }
    assert.deepEqual(brokerRecord((await first.listPendingWork())[0]), brokerRecord(descriptor));
    assert.deepEqual(brokerRecord((await first.listDurableHandoffs())[0]), brokerRecord(handoff));
  });

  test(`${backend}: broker concurrent writers compare against the committed lease in one transaction`, async () => {
    const { first, broker } = await brokerEnvironment(backend);
    await first.persistBrokerWork(brokerWork());
    const results = await Promise.allSettled([
      first.persistBrokerWork(brokerWork({ leaseEpoch: 3 })),
      broker().persistBrokerWork(brokerWork({ leaseEpoch: 2 })),
    ]);
    assert.equal(results[0].status, "fulfilled");
    assert.equal(results[1].status, "rejected");
    brokerError(results[1].reason, "broker_restart_reconciliation_failed");
    const crossRecord = await Promise.allSettled([
      first.persistDurableHandoff(brokerWork({ leaseEpoch: 5 })),
      broker().persistBrokerWork(brokerWork({ leaseEpoch: 4 })),
    ]);
    assert.equal(crossRecord[0].status, "fulfilled");
    assert.equal(crossRecord[1].status, "rejected");
    brokerError(crossRecord[1].reason, "broker_restart_reconciliation_failed");
    assert.equal((await broker().listPendingWork())[0].leaseEpoch, 3);
    assert.equal((await broker().listDurableHandoffs())[0].leaseEpoch, 5);
  });

  test(`${backend}: broker registration changes and work admission cannot cross capability versions`, async () => {
    const { first, broker } = await brokerEnvironment(backend);
    const results = await Promise.allSettled([
      first.registerBroker(brokerRegistration({ capabilityManifestVersion: "caps-v2" })),
      broker().persistBrokerWork(brokerWork()),
    ]);
    assert.equal(results[0].status, "fulfilled");
    assert.equal(results[1].status, "rejected");
    brokerError(results[1].reason, "capability_manifest_mismatch_on_restart");
    assert.equal((await first.readRegistration()).capabilityManifestVersion, "caps-v2");
    assert.equal((await first.listPendingWork()).length, 0);
    await first.persistBrokerWork(brokerWork({ capabilityManifestVersion: "caps-v2" }));
    await assert.rejects(broker().registerBroker(brokerRegistration()),
      error => brokerError(error, "capability_manifest_mismatch_on_restart"));
    assert.equal((await first.readRegistration()).capabilityManifestVersion, "caps-v2");
  });

  test(`${backend}: broker manifest removal cannot make retained work adoptable by another app`, async () => {
    const { first, broker } = await brokerEnvironment(backend);
    await first.persistBrokerWork(brokerWork());
    assert.equal(await first.clearRegistration(), true);
    const request = brokerRegistration();
    request.admission.appNamespace = "another-app";
    await assert.rejects(broker().registerBroker(request),
      error => brokerError(error, "broker_restart_reconciliation_failed"));
    assert.equal(await first.readRegistration(), null);
    assert.equal((await first.listPendingWork())[0].idempotencyKey, "event-1");
    assert.equal(await first.clearBrokerState(), 1);
    assert.equal((await first.registerBroker(request)).admission.appNamespace, "another-app");
  });

  test(`${backend}: broker owns nested input before waiting for storage`, async () => {
    const { first, broker } = await brokerEnvironment(backend);
    const request = brokerWork({ metadata: { nested: { accepted: true } } });
    const writing = first.persistBrokerWork(request);
    request.brokerWorkId = "retargeted";
    request.leaseEpoch = 99;
    request.metadata.nested.accepted = false;
    const descriptor = await writing;
    assert.equal(descriptor.brokerWorkId, "work-1");
    assert.equal(descriptor.leaseEpoch, 1);
    assert.equal(descriptor.metadata.nested.accepted, true);
    descriptor.metadata.nested.accepted = false;
    assert.equal((await broker().listPendingWork())[0].metadata.nested.accepted, true);
  });

  test(`${backend}: broker rejects ambiguous lease epochs before mutating durable state`, async () => {
    const { first } = await brokerEnvironment(backend);
    await first.persistBrokerWork(brokerWork({ leaseEpoch: Number.MAX_SAFE_INTEGER }));
    for (const leaseEpoch of [-1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
      for (const operation of ["persistBrokerWork", "persistDurableHandoff"]) {
        await assert.rejects(first[operation](brokerWork({ leaseEpoch })),
          error => brokerError(error, "serialization_failed"));
      }
    }
    assert.equal((await first.listPendingWork())[0].leaseEpoch, Number.MAX_SAFE_INTEGER);
    assert.equal((await first.listDurableHandoffs()).length, 0);
  });

  test(`${backend}: broker failed publication retains the old lease and unrelated namespace records`, async () => {
    const env = await brokerEnvironment(backend);
    const artifact = env.store({}, "broker-transactions");
    await artifact.persistArtifact(custom("retained-evidence"));
    await env.first.persistBrokerWork(brokerWork());
    env.failSet(key => key === "broker_work:work-1");
    await assert.rejects(env.first.persistBrokerWork(brokerWork({ leaseEpoch: 2 })),
      error => brokerError(error, "storage_failed"));
    assert.equal((await env.first.listPendingWork())[0].leaseEpoch, 1);
    assert.equal(bytesText((await artifact.exportArtifact("retained-evidence")).bytes), "retained-evidence");
    assert.equal((await env.first.persistBrokerWork(brokerWork({ leaseEpoch: 2 }))).leaseEpoch, 2);
  });

  test(`${backend}: broker rejects persisted identity drift and permits explicit corrupt-record cleanup`, async () => {
    const env = await brokerEnvironment(backend);
    const record = await env.first.persistBrokerWork(brokerWork());
    const storage = new env.api.BrowserStorage({ backend, globalObject: env.host });
    await storage.set("broker-transactions", "broker_work:work-1",
      new TextEncoder().encode(JSON.stringify({ ...record, brokerWorkId: "another-work" })));
    await assert.rejects(env.first.listPendingWork(),
      error => brokerError(error, "broker_restart_reconciliation_failed"));
    await assert.rejects(env.first.persistDurableHandoff(brokerWork()),
      error => brokerError(error, "broker_restart_reconciliation_failed"));
    assert.equal(await env.first.deleteBrokerWork("work-1"), true);
    assert.equal((await env.first.listPendingWork()).length, 0);
    assert.equal((await env.first.persistBrokerWork(brokerWork())).brokerWorkId, "work-1");
  });

  test(`${backend}: broker rejects durable registration from another service-worker origin`, async () => {
    const { first, broker, brokerHost } = await brokerEnvironment(backend);
    const foreign = broker({ globalObject: {
      ...brokerHost, location: { origin: "https://other.example.test" },
    } });
    await assert.rejects(foreign.readRegistration(),
      error => brokerError(error, "service_worker_registration_scope_mismatch"));
    await assert.rejects(foreign.persistBrokerWork(brokerWork()),
      error => brokerError(error, "service_worker_registration_scope_mismatch"));
    assert.equal((await first.listPendingWork()).length, 0);
  });

  test(`${backend}: broker refuses malformed durable identity instead of normalizing it into authority`, async () => {
    const env = await brokerEnvironment(backend);
    const registration = brokerRecord(await env.first.readRegistration());
    const storage = new env.api.BrowserStorage({ backend, globalObject: env.host });
    for (const record of [
      { ...registration, backend: "foreign-storage" },
      { ...registration, admission: { ...registration.admission, appVersionMajor: -1 } },
      { ...registration, admission: { ...registration.admission, appVersionMajor: 1.5 } },
      { ...registration, admission: { ...registration.admission, brokerProtocolVersion: 1.5 } },
      { ...registration, admission: { ...registration.admission, brokerProtocolVersion: Number.MAX_SAFE_INTEGER + 1 } },
      { ...registration, registeredAtMs: -1 },
      { ...registration, updatedAtMs: 1.5 },
    ]) {
      const bytes = new TextEncoder().encode(JSON.stringify(record));
      await storage.set("broker-transactions", "__service_worker_broker_registration__", bytes);
      await assert.rejects(env.first.readRegistration(),
        error => brokerError(error, "broker_restart_reconciliation_failed"));
      await assert.rejects(env.first.persistBrokerWork(brokerWork()),
        error => brokerError(error, "broker_restart_reconciliation_failed"));
      assert.deepEqual(Array.from(await storage.get("broker-transactions", "__service_worker_broker_registration__")),
        Array.from(bytes));
    }
    assert.equal(await env.first.clearBrokerState(), 1);
    await env.first.registerBroker(brokerRegistration());
    assert.equal((await env.first.persistBrokerWork(brokerWork())).leaseEpoch, 1);
  });

  test(`${backend}: broker invalid clocks cannot publish unreadable durable records`, async () => {
    const { first, broker } = await brokerEnvironment(backend);
    const registration = brokerRecord(await first.readRegistration());
    for (const now of [NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
      const store = broker({ now: () => now });
      for (const operation of [
        () => store.registerBroker(brokerRegistration()),
        () => store.setLifecycleState("draining"),
        () => store.persistBrokerWork(brokerWork()),
        () => store.persistDurableHandoff(brokerWork()),
      ]) {
        await assert.rejects(operation(), error => brokerError(error, "serialization_failed"));
      }
    }
    assert.deepEqual(brokerRecord(await first.readRegistration()), registration);
    assert.equal((await first.listPendingWork()).length, 0);
    assert.equal((await first.listDurableHandoffs()).length, 0);
  });
}

test("indexeddb: broker lifecycle updates cannot resurrect a concurrently cleared registration", async () => {
  const env = await brokerEnvironment("indexeddb");
  let clearing;
  let armed = true;
  env.observeReads(key => {
    if (armed && key === "__service_worker_broker_registration__") {
      armed = false;
      clearing = env.broker().clearRegistration();
    }
  });
  await env.first.setLifecycleState("draining");
  assert.ok(clearing, "start the clear while the lifecycle update is reading its registration");
  assert.equal(await clearing, true);
  assert.equal(await env.broker().readRegistration(), null);
});

test("indexeddb: broker asynchronous transaction abort cannot publish or advance a lease", async () => {
  const env = await brokerEnvironment("indexeddb");
  await env.first.persistBrokerWork(brokerWork());
  env.abortAfterPut(key => key === "broker_work:work-1");
  await assert.rejects(env.first.persistBrokerWork(brokerWork({ leaseEpoch: 2 })),
    error => brokerError(error, "storage_failed"));
  assert.equal((await env.broker().listPendingWork())[0].leaseEpoch, 1);
  assert.equal((await env.broker().persistBrokerWork(brokerWork({ leaseEpoch: 2 }))).leaseEpoch, 2);
});

test("localstorage: broker Web Locks fence independent SDK realms and snapshot queued input", async () => {
  const env = await brokerEnvironment("localstorage");
  const secondApi = await sdk(env.host);
  let release;
  let tail = new Promise(resolve => { release = resolve; });
  const requests = [];
  env.brokerHost.navigator = { locks: { request(name, options, callback) {
    requests.push({ name, mode: options.mode });
    const pending = tail.then(callback);
    tail = pending.catch(() => undefined);
    return pending;
  } } };
  const second = new secondApi.BrowserServiceWorkerBrokerStore({
    backend: "localstorage", globalObject: env.brokerHost, namespace: "broker-transactions",
  });
  const request = brokerWork({ leaseEpoch: 3, metadata: { nested: { accepted: true } } });
  const high = env.first.persistBrokerWork(request);
  const low = second.persistBrokerWork(brokerWork({ leaseEpoch: 2 }));
  request.metadata.nested.accepted = false;
  assert.equal(requests.length, 2);
  assert.equal(requests[0].name, requests[1].name);
  assert.equal(requests[0].mode, "exclusive");
  assert.equal(requests[1].mode, "exclusive");
  release();
  const results = await Promise.allSettled([high, low]);
  assert.equal(results[0].status, "fulfilled");
  assert.equal(results[1].status, "rejected");
  brokerError(results[1].reason, "broker_restart_reconciliation_failed");
  const record = (await second.listPendingWork())[0];
  assert.equal(record.leaseEpoch, 3);
  assert.equal(record.metadata.nested.accepted, true);
  assert.equal(requests.at(-1).mode, "shared");
});
