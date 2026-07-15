/// <reference lib="webworker" />

import {
  abiFingerprint,
  abiVersion,
  BROWSER_ARTIFACT_DOWNLOAD_UNSUPPORTED_CODE,
  BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE,
  BROWSER_MAIN_THREAD_DIRECT_RUNTIME_LANE,
  createBrowserArtifactStore,
  createBrowserRuntimeSelection,
  createBrowserScopeSelection,
  createBrowserStorage,
  detectBrowserExecutionLadder,
  detectBrowserRuntimeSupport,
  detectBrowserStorageSupport,
  formatOutcomeFailure,
  reportBrowserLaneUnhealthy,
  resetBrowserLaneHealth,
  type BrowserRuntime,
} from "@asupersync/browser";

declare const self: DedicatedWorkerGlobalScope;

type ShutdownRequest = {
  type: "shutdown";
  reason?: string;
};

type RuntimeSelection = Awaited<ReturnType<typeof createBrowserRuntimeSelection>>;
type ScopeSelection = Awaited<ReturnType<typeof createBrowserScopeSelection>>;

const WORKER_STORAGE_NAMESPACE = "worker_fixture_storage";
const WORKER_STORAGE_DB_NAME = "asupersync-fixture";
const WORKER_STORAGE_STORE_NAME = "browser-fixture";
const WORKER_ARTIFACT_NAMESPACE = "worker_fixture_artifacts";
const WORKER_ARTIFACT_QUOTA_NAMESPACE = "worker_fixture_artifacts_quota";
const WORKER_SCENARIO_ID = "DEDICATED-WORKER-CONSUMER";
const WORKER_SCOPE_LABEL = "dedicated-worker-fixture";
const WORKER_LANE_HEALTH_SCOPE_KEY = "dedicated-worker-fixture-lane-health";
const WORKER_RUNTIME_SELECTION_BASELINE_MARKER = "worker-runtime-selection-baseline";
const WORKER_SCOPE_SELECTION_BASELINE_MARKER = "worker-scope-selection-baseline";
const WORKER_SCOPE_SELECTION_PREFERRED_MAIN_THREAD_MARKER =
  "worker-scope-selection-preferred-main-thread";
const WORKER_LANE_HEALTH_RETRYING_MARKER = "worker-lane-health-retrying";
const WORKER_EXECUTION_LADDER_RETRYING_MARKER = "worker-execution-ladder-retrying";
const WORKER_LANE_HEALTH_DEMOTION_MARKER = "worker-lane-health-demotion";
const WORKER_RUNTIME_SELECTION_DEMOTED_MARKER = "worker-runtime-selection-demoted";
const WORKER_RUNTIME_SELECTION_PREREQUISITE_LOSS_MARKER =
  "worker-runtime-selection-prerequisite-loss";
const WORKER_LANE_HEALTH_RESET_MARKER = "worker-lane-health-reset";
const WORKER_RUNTIME_SELECTION_RECOVERED_MARKER = "worker-runtime-selection-recovered";
const WORKER_STORAGE_SUPPORT_MARKER = "worker-storage-support";
const WORKER_STORAGE_ROUNDTRIP_MARKER = "worker-storage-roundtrip";
const WORKER_STORAGE_ARTIFACT_MARKER = "worker-storage-artifact-export-handoff";
const WORKER_ARTIFACT_EXPORT_MARKER = "worker-artifact-archive";
const WORKER_ARTIFACT_DOWNLOAD_GUARD_MARKER = "worker-artifact-download-unavailable";
const WORKER_ARTIFACT_QUOTA_GUARD_MARKER = "worker-artifact-quota-guard";
const WORKER_ARTIFACT_CLEANUP_MARKER = "worker-artifact-cleanup";

let runtimeHandle: BrowserRuntime | null = null;
let scopeHandle: { close: () => void } | null = null;

function summarizeOutcome(
  outcome: RuntimeSelection["outcome"] | ScopeSelection["outcome"],
): {
  outcome: string | null;
  failureCode: string | null;
  failureMessage: string | null;
} {
  if (!outcome) {
    return {
      outcome: null,
      failureCode: null,
      failureMessage: null,
    };
  }

  return {
    outcome: outcome.outcome,
    failureCode: outcome.outcome === "err" ? outcome.failure.code : null,
    failureMessage: outcome.outcome === "err" ? outcome.failure.message : null,
  };
}

function summarizeSelection(
  marker: string,
  executionLadder: RuntimeSelection["executionLadder"] | ScopeSelection["executionLadder"],
  outcome: RuntimeSelection["outcome"] | ScopeSelection["outcome"],
  runtimePresent: boolean,
  scopePresent: boolean,
): Record<string, unknown> {
  const outcomeSummary = summarizeOutcome(outcome);
  return {
    marker,
    supported: executionLadder.supported,
    preferredLane: executionLadder.preferredLane,
    selectedLane: executionLadder.selectedLane,
    reasonCode: executionLadder.reasonCode,
    message: executionLadder.message,
    guidance: executionLadder.guidance,
    reproCommand: executionLadder.reproCommand,
    hostRole: executionLadder.hostRole,
    runtimeContext: executionLadder.runtimeContext,
    runtimePresent,
    scopePresent,
    outcome: outcomeSummary.outcome,
    failureCode: outcomeSummary.failureCode,
    failureMessage: outcomeSummary.failureMessage,
    health: {
      scopeKey: executionLadder.health.scopeKey,
      status: executionLadder.health.status,
      failureCount: executionLadder.health.failureCount,
      retryBudgetRemaining: executionLadder.health.retryBudgetRemaining,
      cooldownMs: executionLadder.health.cooldownMs,
      cooldownUntilMs: executionLadder.health.cooldownUntilMs,
      lastTrigger: executionLadder.health.lastTrigger,
      lastMessage: executionLadder.health.lastMessage,
      demotedToLaneId: executionLadder.health.demotedToLaneId,
    },
    candidateReasons: executionLadder.candidates.map((candidate) => ({
      laneId: candidate.laneId,
      available: candidate.available,
      selected: candidate.selected,
      reasonCode: candidate.reasonCode,
    })),
  };
}

function summarizeExecutionLadder(
  marker: string,
  executionLadder: RuntimeSelection["executionLadder"],
): Record<string, unknown> {
  return summarizeSelection(marker, executionLadder, null, false, false);
}

function summarizeLaneHealth(
  marker: string,
  health: ReturnType<typeof reportBrowserLaneUnhealthy>,
): Record<string, unknown> {
  return {
    marker,
    scopeKey: health.scopeKey,
    laneId: health.laneId,
    status: health.status,
    failureCount: health.failureCount,
    retryBudgetRemaining: health.retryBudgetRemaining,
    cooldownMs: health.cooldownMs,
    cooldownUntilMs: health.cooldownUntilMs,
    lastTrigger: health.lastTrigger,
    lastMessage: health.lastMessage,
    demotedToLaneId: health.demotedToLaneId,
  };
}

function closeRuntimeSelection(selection: RuntimeSelection): void {
  selection.runtime?.close();
}

function closeScopeSelection(selection: ScopeSelection): void {
  selection.scope?.close();
  selection.runtime?.close();
}

function errorCode(error: unknown): string | null {
  if (!error || typeof error !== "object" || !("code" in error)) {
    return null;
  }
  const value = (error as { code?: unknown }).code;
  return typeof value === "string" ? value : null;
}

function errorReason(error: unknown): string | null {
  if (!error || typeof error !== "object" || !("diagnostics" in error)) {
    return null;
  }
  const diagnostics = (
    error as {
      diagnostics?: {
        reason?: unknown;
      };
    }
  ).diagnostics;
  return typeof diagnostics?.reason === "string" ? diagnostics.reason : null;
}

async function rejectsWithTypeError(
  operation: () => Promise<unknown>,
): Promise<boolean> {
  try {
    await operation();
    return false;
  } catch (error) {
    return error instanceof TypeError;
  }
}

function awaitFixtureIndexedDbRequest<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("fixture IndexedDB request failed"));
  });
}

function awaitFixtureIndexedDbTransaction(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(
      transaction.error ?? new Error("fixture IndexedDB transaction failed"),
    );
    transaction.onabort = () => reject(
      transaction.error ?? new Error("fixture IndexedDB transaction aborted"),
    );
  });
}

async function withFixtureIndexedDb<T>(
  operation: (database: IDBDatabase) => Promise<T>,
): Promise<T> {
  const request = self.indexedDB.open(WORKER_STORAGE_DB_NAME, 1);
  const database = await awaitFixtureIndexedDbRequest(request);
  try {
    return await operation(database);
  } finally {
    database.close();
  }
}

async function fixtureIndexedDbKeys(): Promise<string[]> {
  return withFixtureIndexedDb(async (database) => {
    const transaction = database.transaction(WORKER_STORAGE_STORE_NAME, "readonly");
    const keys = await awaitFixtureIndexedDbRequest(
      transaction.objectStore(WORKER_STORAGE_STORE_NAME).getAllKeys(),
    );
    return keys.filter((key): key is string => typeof key === "string");
  });
}

async function fixtureIndexedDbKeyAddedBy(
  operation: () => Promise<void>,
): Promise<string> {
  const keysBefore = await fixtureIndexedDbKeys();
  await operation();
  const keysAfter = await fixtureIndexedDbKeys();
  const keysBeforeSet = new Set(keysBefore);
  const addedKeys = keysAfter.filter((key) => !keysBeforeSet.has(key));
  if (addedKeys.length !== 1) {
    throw new Error(`expected one raw IndexedDB key, found ${addedKeys.length}`);
  }
  return addedKeys[0];
}

async function readFixtureIndexedDbValue(key: string): Promise<unknown> {
  return withFixtureIndexedDb(async (database) => {
    const transaction = database.transaction(WORKER_STORAGE_STORE_NAME, "readonly");
    return awaitFixtureIndexedDbRequest(
      transaction.objectStore(WORKER_STORAGE_STORE_NAME).get(key),
    );
  });
}

async function writeFixtureIndexedDbValue(key: string, value: unknown): Promise<void> {
  await withFixtureIndexedDb(async (database) => {
    const transaction = database.transaction(WORKER_STORAGE_STORE_NAME, "readwrite");
    transaction.objectStore(WORKER_STORAGE_STORE_NAME).put(value, key);
    await awaitFixtureIndexedDbTransaction(transaction);
  });
}

async function deleteFixtureIndexedDbKey(key: string): Promise<void> {
  await withFixtureIndexedDb(async (database) => {
    const transaction = database.transaction(WORKER_STORAGE_STORE_NAME, "readwrite");
    transaction.objectStore(WORKER_STORAGE_STORE_NAME).delete(key);
    await awaitFixtureIndexedDbTransaction(transaction);
  });
}

function hasExactCompactBytes(value: unknown, expected: readonly number[]): boolean {
  return value instanceof Uint8Array
    && value.byteOffset === 0
    && value.buffer.byteLength === value.byteLength
    && value.byteLength === expected.length
    && expected.every((byte, index) => value[index] === byte);
}

async function withShadowedGlobalProperty<T>(
  globalObject: Record<string, unknown>,
  key: string,
  operation: (shadowGlobalObject: Record<string, unknown>) => Promise<T> | T,
): Promise<{
  simulated: boolean;
  skippedReason: string | null;
  value: T | null;
}> {
  const shadowGlobalObject = new Proxy(globalObject, {
    get(target, property, receiver) {
      if (property === key) {
        return undefined;
      }
      return Reflect.get(target, property, receiver);
    },
    has(target, property) {
      if (property === key) {
        return false;
      }
      return Reflect.has(target, property);
    },
    getOwnPropertyDescriptor(target, property) {
      if (property === key) {
        return undefined;
      }
      return Reflect.getOwnPropertyDescriptor(target, property);
    },
  }) as Record<string, unknown>;

  return {
    simulated: true,
    skippedReason: null,
    value: await operation(shadowGlobalObject),
  };
}

async function bootstrap(): Promise<void> {
  const workerGlobalObject = self as unknown as Record<string, unknown>;
  const laneHealthPolicy = {
    maxConsecutiveFailures: 2,
    cooldownMs: 60_000,
  } as const;
  const support = detectBrowserRuntimeSupport(workerGlobalObject);
  const storageSupport = detectBrowserStorageSupport("indexeddb", workerGlobalObject);
  const runtimeSelectionBaseline = await createBrowserRuntimeSelection({
    globalObject: workerGlobalObject,
  });
  const scopeSelectionBaseline = await createBrowserScopeSelection({
    globalObject: workerGlobalObject,
    label: WORKER_SCOPE_LABEL,
  });
  if (scopeSelectionBaseline.runtime && scopeSelectionBaseline.scope) {
    runtimeHandle = scopeSelectionBaseline.runtime;
    scopeHandle = scopeSelectionBaseline.scope;
  }
  const scopeSelectionPreferredMainThread = await createBrowserScopeSelection({
    globalObject: workerGlobalObject,
    label: "dedicated-worker-preferred-main-thread",
    preferredLane: BROWSER_MAIN_THREAD_DIRECT_RUNTIME_LANE,
  });
  const laneHealthRetrying = reportBrowserLaneUnhealthy({
    globalObject: workerGlobalObject,
    laneId: BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE,
    trigger: "worker_crash",
    message: WORKER_LANE_HEALTH_RETRYING_MARKER,
    healthScopeKey: WORKER_LANE_HEALTH_SCOPE_KEY,
    healthPolicy: laneHealthPolicy,
  });
  const executionLadderRetrying = detectBrowserExecutionLadder({
    globalObject: workerGlobalObject,
    preferredLane: BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE,
    healthScopeKey: WORKER_LANE_HEALTH_SCOPE_KEY,
    healthPolicy: laneHealthPolicy,
  });
  const laneHealthDemotion = reportBrowserLaneUnhealthy({
    globalObject: workerGlobalObject,
    laneId: BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE,
    trigger: "worker_bootstrap_timeout",
    message: WORKER_LANE_HEALTH_DEMOTION_MARKER,
    healthScopeKey: WORKER_LANE_HEALTH_SCOPE_KEY,
    healthPolicy: laneHealthPolicy,
  });
  const runtimeSelectionDemoted = await createBrowserRuntimeSelection({
    globalObject: workerGlobalObject,
    preferredLane: BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE,
    healthScopeKey: WORKER_LANE_HEALTH_SCOPE_KEY,
    healthPolicy: laneHealthPolicy,
  });
  const prerequisiteLossSimulation = await withShadowedGlobalProperty(
    workerGlobalObject,
    "WebAssembly",
    async (shadowGlobalObject) =>
      createBrowserRuntimeSelection({
        globalObject: shadowGlobalObject,
        preferredLane: BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE,
        healthScopeKey: WORKER_LANE_HEALTH_SCOPE_KEY,
        healthPolicy: laneHealthPolicy,
      }),
  );
  const runtimeSelectionPrerequisiteLoss = prerequisiteLossSimulation.value;
  const laneHealthReset = resetBrowserLaneHealth({
    globalObject: workerGlobalObject,
    laneId: BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE,
    healthScopeKey: WORKER_LANE_HEALTH_SCOPE_KEY,
    healthPolicy: laneHealthPolicy,
  });
  const runtimeSelectionRecovered = await createBrowserRuntimeSelection({
    globalObject: workerGlobalObject,
    preferredLane: BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE,
    healthScopeKey: WORKER_LANE_HEALTH_SCOPE_KEY,
    healthPolicy: laneHealthPolicy,
  });

  closeRuntimeSelection(runtimeSelectionBaseline);
  closeScopeSelection(scopeSelectionPreferredMainThread);
  closeRuntimeSelection(runtimeSelectionDemoted);
  if (runtimeSelectionPrerequisiteLoss !== null) {
    closeRuntimeSelection(runtimeSelectionPrerequisiteLoss);
  }
  closeRuntimeSelection(runtimeSelectionRecovered);

  let storageExercise: Record<string, unknown> | null = null;
  let artifactExercise: Record<string, unknown> | null = null;
  if (storageSupport.supported) {
    const storage = createBrowserStorage({
      backend: "indexeddb",
      dbName: WORKER_STORAGE_DB_NAME,
      storeName: WORKER_STORAGE_STORE_NAME,
      globalObject: workerGlobalObject,
    });
    const artifactStore = createBrowserArtifactStore({
      backend: "indexeddb",
      dbName: WORKER_STORAGE_DB_NAME,
      storeName: WORKER_STORAGE_STORE_NAME,
      namespace: WORKER_ARTIFACT_NAMESPACE,
      globalObject: workerGlobalObject,
      retention: {
        maxArtifacts: 4,
        maxArtifactBytes: 16 * 1024,
        maxTotalBytes: 64 * 1024,
        quotaStrategy: "evict_oldest",
      },
    });
    const quotaStore = createBrowserArtifactStore({
      backend: "indexeddb",
      dbName: WORKER_STORAGE_DB_NAME,
      storeName: WORKER_STORAGE_STORE_NAME,
      namespace: WORKER_ARTIFACT_QUOTA_NAMESPACE,
      globalObject: workerGlobalObject,
      retention: {
        maxArtifacts: 2,
        maxArtifactBytes: 1024,
        maxTotalBytes: 1024,
        quotaStrategy: "fail",
      },
    });

    let indexedDbAccessesDuringIllFormedValidation = 0;
    const noIoGlobalObject = new Proxy(workerGlobalObject, {
      get(target, property) {
        if (property === "indexedDB") {
          indexedDbAccessesDuringIllFormedValidation += 1;
          throw new Error("ill-formed storage input must reject before IndexedDB access");
        }
        return Reflect.get(target, property, target);
      },
    });
    const noIoStorage = createBrowserStorage({
      backend: "indexeddb",
      dbName: WORKER_STORAGE_DB_NAME,
      storeName: WORKER_STORAGE_STORE_NAME,
      globalObject: noIoGlobalObject,
    });
    const noIoArtifactStore = createBrowserArtifactStore({
      backend: "indexeddb",
      dbName: WORKER_STORAGE_DB_NAME,
      storeName: WORKER_STORAGE_STORE_NAME,
      namespace: `${WORKER_ARTIFACT_NAMESPACE}_no_io`,
      globalObject: noIoGlobalObject,
    });
    const noIoIllFormedKey = String.fromCharCode(0xd800);
    const noIoIllFormedNamespace = String.fromCharCode(0xdc00);
    const noIoIllFormedArtifactId = String.fromCharCode(0xd801);
    const illFormedKeyRejectedBeforeIo = await rejectsWithTypeError(() =>
      noIoStorage.set("valid", noIoIllFormedKey, new Uint8Array([0x01])),
    );
    const illFormedNamespaceRejectedBeforeIo = await rejectsWithTypeError(() =>
      noIoStorage.clearNamespace(noIoIllFormedNamespace),
    );
    const illFormedArtifactPersistRejectedBeforeIo = await rejectsWithTypeError(
      () => noIoArtifactStore.persistEvidenceArtifact(new Uint8Array([0x02]), {
        id: noIoIllFormedArtifactId,
        format: "binary",
      }),
    );
    const illFormedArtifactExportRejectedBeforeIo = await rejectsWithTypeError(
      () => noIoArtifactStore.exportArtifact(noIoIllFormedArtifactId),
    );
    const illFormedArtifactDeleteRejectedBeforeIo = await rejectsWithTypeError(
      () => noIoArtifactStore.deleteArtifact(noIoIllFormedArtifactId),
    );
    const illFormedValidationBeforeIndexedDbAccess = illFormedKeyRejectedBeforeIo
      && illFormedNamespaceRejectedBeforeIo
      && illFormedArtifactPersistRejectedBeforeIo
      && illFormedArtifactExportRejectedBeforeIo
      && illFormedArtifactDeleteRejectedBeforeIo
      && indexedDbAccessesDuringIllFormedValidation === 0;
    if (!illFormedValidationBeforeIndexedDbAccess) {
      throw new Error(
        `expected ill-formed storage input to reject before IndexedDB access, observed ${indexedDbAccessesDuringIllFormedValidation} accesses`,
      );
    }

    await storage.clearNamespace(WORKER_STORAGE_NAMESPACE);
    await artifactStore.clearArtifacts();
    await quotaStore.clearArtifacts();

    const rawKeysBeforeIllFormedArtifactId = await fixtureIndexedDbKeys();
    const illFormedArtifactId = `artifact-${String.fromCharCode(0xd801)}`;
    const illFormedArtifactPersistRejected = await rejectsWithTypeError(
      () => artifactStore.persistEvidenceArtifact(new Uint8Array([0xa6]), {
        id: illFormedArtifactId,
        format: "binary",
      }),
    );
    const illFormedArtifactExportRejected = await rejectsWithTypeError(
      () => artifactStore.exportArtifact(illFormedArtifactId),
    );
    const illFormedArtifactDeleteRejected = await rejectsWithTypeError(
      () => artifactStore.deleteArtifact(illFormedArtifactId),
    );
    const rawKeysAfterIllFormedArtifactId = await fixtureIndexedDbKeys();
    const rawKeysAfterIllFormedArtifactIdSet = new Set(
      rawKeysAfterIllFormedArtifactId,
    );
    const illFormedArtifactIdRawKeysUnchanged = rawKeysBeforeIllFormedArtifactId.length
      === rawKeysAfterIllFormedArtifactId.length
      && rawKeysBeforeIllFormedArtifactId.every(
        (key) => rawKeysAfterIllFormedArtifactIdSet.has(key),
      );
    const literalReplacementArtifactId = "artifact-\ufffd";
    const literalReplacementArtifact = await artifactStore.persistEvidenceArtifact(
      new Uint8Array([0xa7]),
      {
        id: literalReplacementArtifactId,
        format: "binary",
      },
    );
    const literalReplacementArtifactExport = await artifactStore.exportArtifact(
      literalReplacementArtifactId,
    );
    const literalReplacementArtifactDeleted = await artifactStore.deleteArtifact(
      literalReplacementArtifactId,
    );
    const literalReplacementArtifactAccepted = literalReplacementArtifact.artifact.id
      === literalReplacementArtifactId
      && hasExactCompactBytes(literalReplacementArtifactExport.bytes, [0xa7])
      && literalReplacementArtifactDeleted;
    if (
      !illFormedArtifactPersistRejected
      || !illFormedArtifactExportRejected
      || !illFormedArtifactDeleteRejected
      || !illFormedArtifactIdRawKeysUnchanged
    ) {
      throw new Error("expected ill-formed UTF-16 artifact ids to fail before storage I/O");
    }
    if (!literalReplacementArtifactAccepted) {
      throw new Error("expected a literal U+FFFD artifact id to round-trip");
    }

    await storage.set(
      WORKER_STORAGE_NAMESPACE,
      "ready",
      new TextEncoder().encode("worker-storage-ready"),
    );
    const storedValue = await storage.get(WORKER_STORAGE_NAMESPACE, "ready");
    const listedKeys = await storage.listKeys(WORKER_STORAGE_NAMESPACE);
    if (storedValue === null) {
      throw new Error("expected dedicated-worker storage round-trip payload to be readable");
    }
    if (!listedKeys.includes("ready")) {
      throw new Error("expected dedicated-worker storage namespace to retain the ready key");
    }

    const replacementNamespace = `${WORKER_STORAGE_NAMESPACE}_unicode_\ufffd`;
    const replacementKey = "sentinel-\ufffd";
    await storage.clearNamespace(replacementNamespace);
    await storage.set(
      replacementNamespace,
      replacementKey,
      new Uint8Array([0xa5]),
    );
    const rawKeysBeforeIllFormedInput = await fixtureIndexedDbKeys();
    const illFormedKeyRejected = await rejectsWithTypeError(() =>
      storage.set(
        replacementNamespace,
        `sentinel-${String.fromCharCode(0xd800)}`,
        new Uint8Array([0xb5]),
      ),
    );
    const illFormedNamespaceRejected = await rejectsWithTypeError(() =>
      storage.clearNamespace(
        `${WORKER_STORAGE_NAMESPACE}_unicode_${String.fromCharCode(0xdc00)}`,
      ),
    );
    const rawKeysAfterIllFormedInput = await fixtureIndexedDbKeys();
    const illFormedInputRawCountUnchanged = rawKeysAfterIllFormedInput.length
      === rawKeysBeforeIllFormedInput.length;
    const literalReplacementValue = await storage.get(
      replacementNamespace,
      replacementKey,
    );
    const literalReplacementPreserved = hasExactCompactBytes(
      literalReplacementValue,
      [0xa5],
    );
    const validSurrogatePairKey = "emoji-\ud83d\ude00";
    await storage.set(
      replacementNamespace,
      validSurrogatePairKey,
      new Uint8Array([0xf1]),
    );
    const validSurrogatePairValue = await storage.get(
      replacementNamespace,
      validSurrogatePairKey,
    );
    const validSurrogatePairRoundtrip = hasExactCompactBytes(
      validSurrogatePairValue,
      [0xf1],
    );
    const validSurrogatePairListed = (
      await storage.listKeys(replacementNamespace)
    ).includes(validSurrogatePairKey);
    await storage.clearNamespace(replacementNamespace);
    if (!illFormedKeyRejected || !illFormedNamespaceRejected) {
      throw new Error("expected ill-formed UTF-16 storage input to reject with TypeError");
    }
    if (!illFormedInputRawCountUnchanged || !literalReplacementPreserved) {
      throw new Error("expected rejected UTF-16 aliases to preserve raw storage records");
    }
    if (!validSurrogatePairRoundtrip || !validSurrogatePairListed) {
      throw new Error("expected a valid UTF-16 surrogate pair to round-trip");
    }

    const subviewBacking = new Uint8Array(1024 * 1024);
    const subviewOffset = subviewBacking.byteLength / 2;
    subviewBacking[0] = 0xa1;
    subviewBacking[subviewOffset] = 0x31;
    subviewBacking[subviewOffset + 1] = 0x32;
    subviewBacking[subviewBacking.byteLength - 1] = 0xa2;
    const rawSubviewKey = await fixtureIndexedDbKeyAddedBy(() =>
      storage.set(
        WORKER_STORAGE_NAMESPACE,
        "subview",
        subviewBacking.subarray(subviewOffset, subviewOffset + 2),
      ),
    );
    const rawSubviewValue = await readFixtureIndexedDbValue(rawSubviewKey);
    const subviewWriteCompacted = hasExactCompactBytes(rawSubviewValue, [0x31, 0x32]);
    const subviewStoredBackingBytes = rawSubviewValue instanceof Uint8Array
      ? rawSubviewValue.buffer.byteLength
      : null;
    if (!subviewWriteCompacted) {
      throw new Error("expected BrowserStorage to compact subview backing bytes before IndexedDB");
    }

    const legacySubviewBacking = new Uint8Array([0xb1, 0x41, 0x42, 0xb2]);
    await writeFixtureIndexedDbValue(
      rawSubviewKey,
      new DataView(legacySubviewBacking.buffer, 1, 2),
    );
    const legacyRawSubviewValue = await readFixtureIndexedDbValue(rawSubviewKey);
    const legacyRawBacking = legacyRawSubviewValue instanceof DataView
      ? new Uint8Array(legacyRawSubviewValue.buffer)
      : null;
    const legacySubviewRawBackingObserved = legacyRawSubviewValue instanceof DataView
      && legacyRawSubviewValue.byteOffset === 1
      && legacyRawSubviewValue.byteLength === 2
      && legacyRawSubviewValue.buffer.byteLength === 4
      && legacyRawBacking?.[0] === 0xb1
      && legacyRawBacking[3] === 0xb2;
    if (!legacySubviewRawBackingObserved) {
      throw new Error("expected raw IndexedDB to retain the injected legacy DataView backing");
    }
    const legacySubviewValue = await storage.get(
      WORKER_STORAGE_NAMESPACE,
      "subview",
    );
    const legacySubviewReadCompacted = hasExactCompactBytes(
      legacySubviewValue,
      [0x41, 0x42],
    );
    if (!legacySubviewReadCompacted) {
      throw new Error("expected BrowserStorage to compact legacy subview backing bytes on read");
    }

    class SpoofedSubview extends Uint8Array {
      override get byteOffset(): number {
        return 0;
      }

      override get byteLength(): number {
        return 2;
      }

      override get buffer(): ArrayBuffer {
        return new ArrayBuffer(2);
      }
    }

    const subclassBacking = new Uint8Array([0xd1, 0x61, 0x62, 0xd2]);
    const spoofedSubview = new SpoofedSubview(subclassBacking.buffer, 1, 2);
    const rawSpoofedSubviewKey = await fixtureIndexedDbKeyAddedBy(() =>
      storage.set(
        WORKER_STORAGE_NAMESPACE,
        "spoofed-subview",
        spoofedSubview,
      ),
    );
    const spoofedSubviewWriteCompacted = hasExactCompactBytes(
      await readFixtureIndexedDbValue(rawSpoofedSubviewKey),
      [0x61, 0x62],
    );
    if (!spoofedSubviewWriteCompacted) {
      throw new Error("expected BrowserStorage to ignore typed-array subclass accessors");
    }

    const shadowedBacking = new Uint8Array([0xe1, 0x71, 0x72, 0xe2]);
    const shadowedSubview = shadowedBacking.subarray(1, 3);
    Object.defineProperties(shadowedSubview, {
      buffer: { value: new ArrayBuffer(2) },
      byteLength: { value: 2 },
      byteOffset: { value: 0 },
    });
    const rawShadowedSubviewKey = await fixtureIndexedDbKeyAddedBy(() =>
      storage.set(
        WORKER_STORAGE_NAMESPACE,
        "shadowed-subview",
        shadowedSubview,
      ),
    );
    const shadowedSubviewWriteCompacted = hasExactCompactBytes(
      await readFixtureIndexedDbValue(rawShadowedSubviewKey),
      [0x71, 0x72],
    );
    if (!shadowedSubviewWriteCompacted) {
      throw new Error("expected BrowserStorage to ignore shadowed typed-array view properties");
    }

    const proxyKeysBefore = await fixtureIndexedDbKeys();
    const proxiedSubview = new Proxy(
      new Uint8Array([0xf1, 0x81, 0x82, 0xf2]).subarray(1, 3),
      {},
    );
    let proxiedSubviewRejected = false;
    try {
      await storage.set(
        WORKER_STORAGE_NAMESPACE,
        "proxied-subview",
        proxiedSubview,
      );
    } catch (error) {
      proxiedSubviewRejected = error instanceof TypeError
        && error.message
          === "browser storage values must be Uint8Array, ArrayBuffer, ArrayBufferView, or byte[]";
    }
    const proxyKeysAfter = await fixtureIndexedDbKeys();
    const proxyKeysAfterSet = new Set(proxyKeysAfter);
    const proxiedSubviewFailedClosed = proxiedSubviewRejected
      && proxyKeysBefore.length === proxyKeysAfter.length
      && proxyKeysBefore.every((key) => proxyKeysAfterSet.has(key));
    if (!proxiedSubviewFailedClosed) {
      throw new Error("expected BrowserStorage to reject proxied typed-array views without writing");
    }

    const fullArrayBufferKey = await fixtureIndexedDbKeyAddedBy(() =>
      storage.set(
        WORKER_STORAGE_NAMESPACE,
        "full-array-buffer",
        new Uint8Array([0x91, 0x92]).buffer,
      ),
    );
    const fullArrayBufferStoredExactly = hasExactCompactBytes(
      await readFixtureIndexedDbValue(fullArrayBufferKey),
      [0x91, 0x92],
    );
    if (!fullArrayBufferStoredExactly) {
      throw new Error("expected BrowserStorage to preserve full-span ArrayBuffer bytes");
    }

    const fullUint8ArrayKey = await fixtureIndexedDbKeyAddedBy(() =>
      storage.set(
        WORKER_STORAGE_NAMESPACE,
        "full-uint8-array",
        new Uint8Array([0x97, 0x98]),
      ),
    );
    const fullUint8ArrayStoredExactly = hasExactCompactBytes(
      await readFixtureIndexedDbValue(fullUint8ArrayKey),
      [0x97, 0x98],
    );
    if (!fullUint8ArrayStoredExactly) {
      throw new Error("expected BrowserStorage to preserve full-span Uint8Array bytes");
    }

    const dataViewBacking = new Uint8Array([0xa5, 0xa6, 0x93, 0x94, 0xa7]);
    const dataViewKey = await fixtureIndexedDbKeyAddedBy(() =>
      storage.set(
        WORKER_STORAGE_NAMESPACE,
        "data-view",
        new DataView(dataViewBacking.buffer, 2, 2),
      ),
    );
    const dataViewWriteCompacted = hasExactCompactBytes(
      await readFixtureIndexedDbValue(dataViewKey),
      [0x93, 0x94],
    );
    if (!dataViewWriteCompacted) {
      throw new Error("expected BrowserStorage to compact DataView backing bytes");
    }

    const spoofedDataViewBacking = new Uint8Array([0xb5, 0xb6, 0x95, 0x96, 0xb7]);
    const spoofedDataView = new DataView(spoofedDataViewBacking.buffer, 2, 2);
    Object.defineProperties(spoofedDataView, {
      buffer: { value: new ArrayBuffer(2) },
      byteLength: { value: 2 },
      byteOffset: { value: 0 },
    });
    const spoofedDataViewKey = await fixtureIndexedDbKeyAddedBy(() =>
      storage.set(
        WORKER_STORAGE_NAMESPACE,
        "spoofed-data-view",
        spoofedDataView,
      ),
    );
    const spoofedDataViewWriteCompacted = hasExactCompactBytes(
      await readFixtureIndexedDbValue(spoofedDataViewKey),
      [0x95, 0x96],
    );
    if (!spoofedDataViewWriteCompacted) {
      throw new Error("expected BrowserStorage to ignore DataView subclass accessors");
    }

    const emptySubviewBacking = new Uint8Array([0xc5, 0xc6]);
    const emptySubviewKey = await fixtureIndexedDbKeyAddedBy(() =>
      storage.set(
        WORKER_STORAGE_NAMESPACE,
        "empty-subview",
        emptySubviewBacking.subarray(1, 1),
      ),
    );
    const emptySubviewWriteCompacted = hasExactCompactBytes(
      await readFixtureIndexedDbValue(emptySubviewKey),
      [],
    );
    if (!emptySubviewWriteCompacted) {
      throw new Error("expected BrowserStorage to compact an empty subview to empty backing");
    }

    const persisted = await artifactStore.persistEvidenceArtifact(
      {
        marker: WORKER_STORAGE_ARTIFACT_MARKER,
        lane: "worker",
        runtimeOutcome: scopeSelectionBaseline.outcome?.outcome ?? null,
      },
      {
        id: "worker-evidence",
        tags: ["fixture", "worker", "storage", "artifacts"],
      },
    );
    const artifactSubviewBacking = new Uint8Array(1024 * 1024);
    const artifactSubviewOffset = artifactSubviewBacking.byteLength / 2;
    artifactSubviewBacking[0] = 0xc1;
    artifactSubviewBacking[artifactSubviewOffset] = 0x51;
    artifactSubviewBacking[artifactSubviewOffset + 1] = 0x52;
    artifactSubviewBacking[artifactSubviewBacking.byteLength - 1] = 0xc2;
    const artifactKeysBeforeSubview = await fixtureIndexedDbKeys();
    const persistedSubviewArtifact = await artifactStore.persistEvidenceArtifact(
      artifactSubviewBacking.subarray(
        artifactSubviewOffset,
        artifactSubviewOffset + 2,
      ),
      {
        id: "worker-subview-evidence",
        format: "binary",
        contentType: "application/octet-stream",
        tags: ["fixture", "worker", "storage", "subview"],
      },
    );
    const artifactKeysAfterSubview = await fixtureIndexedDbKeys();
    const artifactKeysBeforeSubviewSet = new Set(artifactKeysBeforeSubview);
    const addedArtifactSubviewKeys = artifactKeysAfterSubview.filter(
      (key) => !artifactKeysBeforeSubviewSet.has(key),
    );
    if (addedArtifactSubviewKeys.length !== 1) {
      throw new Error(
        `expected one raw IndexedDB artifact payload key, found ${addedArtifactSubviewKeys.length}`,
      );
    }
    const rawArtifactSubviewValue = await readFixtureIndexedDbValue(
      addedArtifactSubviewKeys[0],
    );
    const artifactSubviewStoredCompacted = hasExactCompactBytes(
      rawArtifactSubviewValue,
      [0x51, 0x52],
    );
    const artifactSubviewStoredBackingBytes = rawArtifactSubviewValue instanceof Uint8Array
      ? rawArtifactSubviewValue.buffer.byteLength
      : null;
    if (!artifactSubviewStoredCompacted) {
      throw new Error("expected artifact retention bytes to match the logical persisted subview");
    }
    const exportedSubviewArtifact = await artifactStore.exportArtifact(
      persistedSubviewArtifact.artifact.id,
    );
    const artifactSubviewExportCompacted = hasExactCompactBytes(
      exportedSubviewArtifact.bytes,
      [0x51, 0x52],
    );
    if (!artifactSubviewExportCompacted) {
      throw new Error("expected artifact export to exclude bytes outside its persisted subview");
    }
    const archive = await artifactStore.exportArchive();

    let downloadFailureCode: string | null = null;
    try {
      await artifactStore.downloadArchive();
    } catch (error) {
      downloadFailureCode = errorCode(error);
    }
    if (downloadFailureCode !== BROWSER_ARTIFACT_DOWNLOAD_UNSUPPORTED_CODE) {
      throw new Error(
        `expected ${BROWSER_ARTIFACT_DOWNLOAD_UNSUPPORTED_CODE} from dedicated-worker downloadArchive()`,
      );
    }

    const quotaSubviewBacking = new Uint8Array(1024 * 1024);
    const quotaSubviewOffset = quotaSubviewBacking.byteLength / 2;
    quotaSubviewBacking.fill(0x71, quotaSubviewOffset, quotaSubviewOffset + 600);
    const quotaSubview = quotaSubviewBacking.subarray(
      quotaSubviewOffset,
      quotaSubviewOffset + 600,
    );
    const quotaKeysBeforeSubview = await fixtureIndexedDbKeys();
    const persistedQuotaSubview = await quotaStore.persistEvidenceArtifact(quotaSubview, {
      id: "worker-quota-a",
      format: "binary",
      contentType: "application/octet-stream",
    });
    const quotaReportedLogicalBytes = persistedQuotaSubview.artifact.byteLength === 600
      && persistedQuotaSubview.totalBytes === 600;
    if (!quotaReportedLogicalBytes) {
      throw new Error("expected artifact quota accounting to report exactly 600 logical bytes");
    }
    const quotaKeysAfterSubview = await fixtureIndexedDbKeys();
    const quotaKeysBeforeSubviewSet = new Set(quotaKeysBeforeSubview);
    const addedQuotaSubviewKeys = quotaKeysAfterSubview.filter(
      (key) => !quotaKeysBeforeSubviewSet.has(key),
    );
    let quotaSubviewStoredCompacted = false;
    let quotaSubviewStoredBackingBytes: number | null = null;
    for (const key of addedQuotaSubviewKeys) {
      const value = await readFixtureIndexedDbValue(key);
      if (hasExactCompactBytes(value, Array.from(quotaSubview))) {
        quotaSubviewStoredCompacted = true;
        quotaSubviewStoredBackingBytes = value instanceof Uint8Array
          ? value.buffer.byteLength
          : null;
        break;
      }
    }
    if (!quotaSubviewStoredCompacted) {
      throw new Error("expected quota accounting to match the physical retained subview bytes");
    }

    let quotaFailureReason: string | null = null;
    try {
      await quotaStore.persistEvidenceArtifact(new Uint8Array(600).fill(0x72), {
        id: "worker-quota-b",
        format: "binary",
        contentType: "application/octet-stream",
      });
    } catch (error) {
      quotaFailureReason = errorReason(error);
    }
    if (quotaFailureReason !== "quota_exceeded") {
      throw new Error("expected quota_exceeded from the dedicated-worker quota guard");
    }

    const namespaceDelimiter = rawSubviewKey.lastIndexOf(":");
    if (namespaceDelimiter < 0) {
      throw new Error("expected raw IndexedDB storage key to contain a namespace delimiter");
    }
    const namespaceRawPrefix = rawSubviewKey.slice(0, namespaceDelimiter + 1);
    const listedKeysBeforeMalformed = await storage.listKeys(WORKER_STORAGE_NAMESPACE);
    const malformedRawKeys = [
      namespaceRawPrefix,
      `${namespaceRawPrefix}_w`,
      `${namespaceRawPrefix}YQ==`,
      `${namespaceRawPrefix}!`,
      `${namespaceRawPrefix}IA`,
      `${namespaceRawPrefix}IGE`,
      `${namespaceRawPrefix}YSA`,
      `${namespaceRawPrefix}\uffffx`,
    ];
    for (const [index, rawKey] of malformedRawKeys.entries()) {
      await writeFixtureIndexedDbValue(rawKey, new Uint8Array([0xd0 + index]));
    }
    const upperBoundOutsiderRawKey = `${namespaceRawPrefix.slice(0, -1)};`;
    await writeFixtureIndexedDbValue(
      upperBoundOutsiderRawKey,
      new Uint8Array([0xef]),
    );
    const listedKeysAfterMalformed = await storage.listKeys(WORKER_STORAGE_NAMESPACE);
    const malformedKeysRejected = listedKeysAfterMalformed.length
      === listedKeysBeforeMalformed.length
      && listedKeysAfterMalformed.every(
        (key, index) => key === listedKeysBeforeMalformed[index],
      );
    if (!malformedKeysRejected) {
      throw new Error("expected malformed and noncanonical IndexedDB keys to be excluded from listing");
    }

    const preservationNamespace = `${WORKER_STORAGE_NAMESPACE}_preserved`;
    await storage.clearNamespace(preservationNamespace);
    await storage.set(preservationNamespace, "sentinel", new Uint8Array([0xe1]));

    const concurrentNamespace = `${WORKER_STORAGE_NAMESPACE}_concurrent`;
    await storage.clearNamespace(concurrentNamespace);
    await storage.set(concurrentNamespace, "first", new Uint8Array([0xc1]));
    await storage.set(concurrentNamespace, "second", new Uint8Array([0xc2]));
    const concurrentStorage = createBrowserStorage({
      backend: "indexeddb",
      dbName: WORKER_STORAGE_DB_NAME,
      storeName: WORKER_STORAGE_STORE_NAME,
      globalObject: workerGlobalObject,
    });
    const storageListKeys = storage.listKeys;
    const concurrentStorageListKeys = concurrentStorage.listKeys;
    let listReaders = 0;
    let releaseListReaders = (): void => {};
    const listReadersReady = new Promise<void>((resolve) => {
      releaseListReaders = resolve;
    });
    const listKeysThroughBarrier = async (
      receiver: typeof storage,
      listKeys: typeof storage.listKeys,
      namespace: string,
    ): Promise<string[]> => {
      const keys = await listKeys.call(receiver, namespace);
      if (namespace === concurrentNamespace) {
        listReaders += 1;
        if (listReaders === 2) {
          releaseListReaders();
        }
        await listReadersReady;
      }
      return keys;
    };
    storage.listKeys = (namespace) =>
      listKeysThroughBarrier(storage, storageListKeys, namespace);
    concurrentStorage.listKeys = (namespace) =>
      listKeysThroughBarrier(
        concurrentStorage,
        concurrentStorageListKeys,
        namespace,
      );
    let concurrentClearResults: number[];
    try {
      concurrentClearResults = await Promise.all([
        storage.clearNamespace(concurrentNamespace),
        concurrentStorage.clearNamespace(concurrentNamespace),
      ]);
    } finally {
      storage.listKeys = storageListKeys;
      concurrentStorage.listKeys = concurrentStorageListKeys;
    }
    concurrentClearResults.sort((left, right) => left - right);
    const concurrentClearSerialized = concurrentClearResults[0] === 0
      && concurrentClearResults[1] === 2;
    if (!concurrentClearSerialized) {
      throw new Error(
        `expected concurrent IndexedDB namespace clears to return [0,2], got ${concurrentClearResults.join(",")}`,
      );
    }

    const rawKeysBeforeClear = await fixtureIndexedDbKeys();
    const rawNamespaceKeyCountBeforeClear = rawKeysBeforeClear.filter(
      (key) => key.startsWith(namespaceRawPrefix),
    ).length;

    const clearedArtifacts = await artifactStore.clearArtifacts();
    const clearedQuotaArtifacts = await quotaStore.clearArtifacts();
    const clearedKeys = await storage.clearNamespace(WORKER_STORAGE_NAMESPACE);
    const rawKeysAfterClear = await fixtureIndexedDbKeys();
    const malformedRawKeysCleared = malformedRawKeys.every(
      (rawKey) => !rawKeysAfterClear.includes(rawKey),
    );
    const namespaceRawKeysCleared = !rawKeysAfterClear.some(
      (rawKey) => rawKey.startsWith(namespaceRawPrefix),
    );
    const clearCountMatchesRawNamespace = clearedKeys === rawNamespaceKeyCountBeforeClear;
    const preservedValue = await storage.get(preservationNamespace, "sentinel");
    const otherNamespacePreserved = hasExactCompactBytes(preservedValue, [0xe1]);
    const upperBoundOutsiderValue = await readFixtureIndexedDbValue(
      upperBoundOutsiderRawKey,
    );
    const upperBoundOutsiderPreserved = hasExactCompactBytes(
      upperBoundOutsiderValue,
      [0xef],
    );
    await deleteFixtureIndexedDbKey(upperBoundOutsiderRawKey);
    await storage.clearNamespace(preservationNamespace);
    if (clearedArtifacts < 1) {
      throw new Error("expected at least one dedicated-worker artifact to be cleared");
    }
    if (clearedQuotaArtifacts < 1) {
      throw new Error("expected at least one dedicated-worker quota artifact to be cleared");
    }
    if (!malformedRawKeysCleared || !namespaceRawKeysCleared) {
      throw new Error("expected namespace clear to delete exact malformed and canonical raw keys");
    }
    if (!clearCountMatchesRawNamespace) {
      throw new Error(
        `expected namespace clear count ${rawNamespaceKeyCountBeforeClear}, got ${clearedKeys}`,
      );
    }
    if (!otherNamespacePreserved) {
      throw new Error("expected namespace clear to preserve records from another namespace");
    }
    if (!upperBoundOutsiderPreserved) {
      throw new Error("expected namespace clear to exclude its exact upper-bound key");
    }

    storageExercise = {
      supportMarker: WORKER_STORAGE_SUPPORT_MARKER,
      roundtripMarker: WORKER_STORAGE_ROUNDTRIP_MARKER,
      artifactMarker: WORKER_STORAGE_ARTIFACT_MARKER,
      backend: storage.backend,
      dbName: storage.dbName,
      storeName: storage.storeName,
      support: storageSupport,
      listedKeys,
      storedValueLength: storedValue?.byteLength ?? null,
      illFormedValidationBeforeIndexedDbAccess,
      indexedDbAccessesDuringIllFormedValidation,
      illFormedArtifactPersistRejected,
      illFormedArtifactExportRejected,
      illFormedArtifactDeleteRejected,
      illFormedArtifactIdRawKeysUnchanged,
      literalReplacementArtifactAccepted,
      illFormedKeyRejected,
      illFormedNamespaceRejected,
      illFormedInputRawCountUnchanged,
      literalReplacementPreserved,
      validSurrogatePairRoundtrip,
      validSurrogatePairListed,
      subviewWriteCompacted,
      subviewStoredBackingBytes,
      legacySubviewRawBackingObserved,
      legacySubviewReadCompacted,
      spoofedSubviewWriteCompacted,
      shadowedSubviewWriteCompacted,
      proxiedSubviewFailedClosed,
      fullArrayBufferStoredExactly,
      fullUint8ArrayStoredExactly,
      dataViewWriteCompacted,
      spoofedDataViewWriteCompacted,
      emptySubviewWriteCompacted,
      malformedKeysRejected,
      malformedRawKeysCleared,
      namespaceRawKeysCleared,
      rawNamespaceKeyCountBeforeClear,
      clearCountMatchesRawNamespace,
      otherNamespacePreserved,
      upperBoundOutsiderPreserved,
      concurrentClearResults,
      concurrentClearSerialized,
      clearedKeys,
    };
    artifactExercise = {
      marker: WORKER_STORAGE_ARTIFACT_MARKER,
      exportMarker: WORKER_ARTIFACT_EXPORT_MARKER,
      downloadGuardMarker: WORKER_ARTIFACT_DOWNLOAD_GUARD_MARKER,
      quotaGuardMarker: WORKER_ARTIFACT_QUOTA_GUARD_MARKER,
      cleanupMarker: WORKER_ARTIFACT_CLEANUP_MARKER,
      namespace: artifactStore.namespace,
      retention: artifactStore.retentionPolicy(),
      persistedArtifactId: persisted.artifact.id,
      persistedSubviewArtifactId: persistedSubviewArtifact.artifact.id,
      artifactSubviewStoredCompacted,
      artifactSubviewStoredBackingBytes,
      artifactSubviewExportCompacted,
      exportedArtifactCount: archive.archive.artifacts.length,
      archiveFilename: archive.filename,
      downloadFailureCode,
      quotaFailureReason,
      quotaReportedLogicalBytes,
      quotaSubviewStoredCompacted,
      quotaSubviewStoredBackingBytes,
      clearedArtifacts,
      clearedQuotaArtifacts,
    };
  }

  self.postMessage({
    type: "worker-bootstrap",
    payload: {
      support,
      storageSupport,
      scenarioId: WORKER_SCENARIO_ID,
      abiVersion: abiVersion(),
      abiFingerprint: abiFingerprint(),
      runtimeOutcome: scopeSelectionBaseline.runtime ? "ok" : null,
      scopeOutcome: scopeSelectionBaseline.outcome?.outcome ?? null,
      runtimeSelectionBaseline: summarizeSelection(
        WORKER_RUNTIME_SELECTION_BASELINE_MARKER,
        runtimeSelectionBaseline.executionLadder,
        runtimeSelectionBaseline.outcome,
        runtimeSelectionBaseline.runtime !== null,
        false,
      ),
      scopeSelectionBaseline: summarizeSelection(
        WORKER_SCOPE_SELECTION_BASELINE_MARKER,
        scopeSelectionBaseline.executionLadder,
        scopeSelectionBaseline.outcome,
        scopeSelectionBaseline.runtime !== null,
        scopeSelectionBaseline.scope !== null,
      ),
      scopeSelectionPreferredMainThread: summarizeSelection(
        WORKER_SCOPE_SELECTION_PREFERRED_MAIN_THREAD_MARKER,
        scopeSelectionPreferredMainThread.executionLadder,
        scopeSelectionPreferredMainThread.outcome,
        scopeSelectionPreferredMainThread.runtime !== null,
        scopeSelectionPreferredMainThread.scope !== null,
      ),
      laneHealthRetrying: summarizeLaneHealth(
        WORKER_LANE_HEALTH_RETRYING_MARKER,
        laneHealthRetrying,
      ),
      executionLadderRetrying: summarizeExecutionLadder(
        WORKER_EXECUTION_LADDER_RETRYING_MARKER,
        executionLadderRetrying,
      ),
      laneHealthDemotion: summarizeLaneHealth(
        WORKER_LANE_HEALTH_DEMOTION_MARKER,
        laneHealthDemotion,
      ),
      runtimeSelectionDemoted: summarizeSelection(
        WORKER_RUNTIME_SELECTION_DEMOTED_MARKER,
        runtimeSelectionDemoted.executionLadder,
        runtimeSelectionDemoted.outcome,
        runtimeSelectionDemoted.runtime !== null,
        false,
      ),
      prerequisiteLossSimulation: {
        marker: WORKER_RUNTIME_SELECTION_PREREQUISITE_LOSS_MARKER,
        simulated: prerequisiteLossSimulation.simulated,
        skippedReason: prerequisiteLossSimulation.skippedReason,
      },
      runtimeSelectionPrerequisiteLoss:
        runtimeSelectionPrerequisiteLoss === null
          ? null
          : summarizeSelection(
              WORKER_RUNTIME_SELECTION_PREREQUISITE_LOSS_MARKER,
              runtimeSelectionPrerequisiteLoss.executionLadder,
              runtimeSelectionPrerequisiteLoss.outcome,
              runtimeSelectionPrerequisiteLoss.runtime !== null,
              false,
            ),
      laneHealthReset: summarizeLaneHealth(
        WORKER_LANE_HEALTH_RESET_MARKER,
        laneHealthReset,
      ),
      runtimeSelectionRecovered: summarizeSelection(
        WORKER_RUNTIME_SELECTION_RECOVERED_MARKER,
        runtimeSelectionRecovered.executionLadder,
        runtimeSelectionRecovered.outcome,
        runtimeSelectionRecovered.runtime !== null,
        false,
      ),
      storageExercise,
      artifactExercise,
    },
  });
}

async function shutdown(reason: string | null): Promise<void> {
  scopeHandle?.close();
  runtimeHandle?.close();

  self.postMessage({
    type: "worker-shutdown-complete",
    reason,
  });
  self.close();
}

self.addEventListener("message", (event: MessageEvent<ShutdownRequest>) => {
  if (event.data?.type === "shutdown") {
    void shutdown(event.data.reason ?? null);
  }
});

void bootstrap().catch((error) => {
  const message =
    error instanceof Error
      ? error.message
      : typeof error === "string"
        ? error
        : formatOutcomeFailure({
            outcome: "err",
            failure: {
              code: "worker_bootstrap_failed",
              recoverability: "transient",
              message: "dedicated worker bootstrap failed",
            },
          });

  self.postMessage({
    type: "worker-bootstrap-failed",
    message,
  });
});
