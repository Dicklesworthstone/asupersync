import {
  abiFingerprint,
  abiVersion,
  createBrowserArtifactStore,
  createBrowserStorage,
  detectBrowserRuntimeSupport,
  detectBrowserStorageSupport,
} from "@asupersync/browser";

const statusElement = document.getElementById("status");
if (!statusElement) {
  throw new Error("status element missing");
}

const VANILLA_STORAGE_NAMESPACE = "vanilla_fixture_storage";
const VANILLA_ARTIFACT_NAMESPACE = "vanilla_fixture_artifacts";
const VANILLA_STORAGE_ARTIFACT_MARKER = "vanilla-storage-artifact-flow";

const support = detectBrowserRuntimeSupport();

const render = (value: unknown): void => {
  statusElement.textContent = JSON.stringify(value, null, 2);
};

async function main(): Promise<void> {
  const version = abiVersion();
  const fingerprint = abiFingerprint();
  const indexedDbSupport = detectBrowserStorageSupport("indexeddb");
  const localStorageSupport = detectBrowserStorageSupport("localstorage");

  let storageExercise: Record<string, unknown> | null = null;
  let artifactExercise: Record<string, unknown> | null = null;

  if (indexedDbSupport.supported) {
    const storage = createBrowserStorage({
      backend: "indexeddb",
      dbName: "asupersync-fixture",
      storeName: "browser-fixture",
    });
    const artifactStore = createBrowserArtifactStore({
      backend: "indexeddb",
      namespace: VANILLA_ARTIFACT_NAMESPACE,
      retention: {
        maxArtifacts: 4,
        maxArtifactBytes: 16 * 1024,
        maxTotalBytes: 64 * 1024,
        quotaStrategy: "evict_oldest",
      },
    });

    await storage.clearNamespace(VANILLA_STORAGE_NAMESPACE);
    await artifactStore.clearArtifacts();

    await storage.set(VANILLA_STORAGE_NAMESPACE, "ready", "browser-storage-ready");
    const storedValue = await storage.get(VANILLA_STORAGE_NAMESPACE, "ready");
    const listedKeys = await storage.listKeys(VANILLA_STORAGE_NAMESPACE);

    const persisted = await artifactStore.persistTraceRecord(
      {
        category: "fixture",
        message: "browser artifact persistence ready",
        severity: "info",
        fields: {
          marker: VANILLA_STORAGE_ARTIFACT_MARKER,
          lane: "vanilla",
        },
      },
      {
        id: "vanilla-trace",
        tags: ["fixture", "storage", "artifacts"],
      },
    );
    const archive = await artifactStore.exportArchive();
    const clearedArtifacts = await artifactStore.clearArtifacts();
    const clearedKeys = await storage.clearNamespace(VANILLA_STORAGE_NAMESPACE);

    storageExercise = {
      marker: VANILLA_STORAGE_ARTIFACT_MARKER,
      backend: storage.backend,
      dbName: storage.dbName,
      storeName: storage.storeName,
      indexedDbSupport,
      localStorageSupport,
      listedKeys,
      storedValueLength: storedValue?.byteLength ?? null,
      clearedKeys,
    };
    artifactExercise = {
      marker: VANILLA_STORAGE_ARTIFACT_MARKER,
      namespace: artifactStore.namespace,
      retention: artifactStore.retentionPolicy(),
      persistedArtifactId: persisted.artifact.id,
      exportedArtifactCount: archive.archive.artifacts.length,
      archiveFilename: archive.filename,
      clearedArtifacts,
      downloadArchiveAvailable: typeof artifactStore.downloadArchive === "function",
    };
  }

  render({
    support,
    abiVersion: version,
    abiFingerprint: fingerprint,
    storageSupport: {
      indexeddb: indexedDbSupport,
      localstorage: localStorageSupport,
    },
    storageExercise,
    artifactExercise,
  });
}

void main().catch((error) => {
  render({
    phase: "error",
    message:
      error instanceof Error ? error.message : typeof error === "string" ? error : "unknown error",
  });
});
