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
      dbName: "asupersync-fixture",
      storeName: "browser-fixture",
      globalObject: workerGlobalObject,
    });
    const artifactStore = createBrowserArtifactStore({
      backend: "indexeddb",
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
      namespace: WORKER_ARTIFACT_QUOTA_NAMESPACE,
      globalObject: workerGlobalObject,
      retention: {
        maxArtifacts: 1,
        maxArtifactBytes: 1024,
        maxTotalBytes: 1024,
        quotaStrategy: "fail",
      },
    });

    await storage.clearNamespace(WORKER_STORAGE_NAMESPACE);
    await artifactStore.clearArtifacts();
    await quotaStore.clearArtifacts();

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

    await quotaStore.persistEvidenceArtifact("q".repeat(600), {
      id: "worker-quota-a",
      format: "text",
    });
    let quotaFailureReason: string | null = null;
    try {
      await quotaStore.persistEvidenceArtifact("q".repeat(600), {
        id: "worker-quota-b",
        format: "text",
      });
    } catch (error) {
      quotaFailureReason = errorReason(error);
    }
    if (quotaFailureReason !== "quota_exceeded") {
      throw new Error("expected quota_exceeded from the dedicated-worker quota guard");
    }

    const clearedArtifacts = await artifactStore.clearArtifacts();
    const clearedQuotaArtifacts = await quotaStore.clearArtifacts();
    const clearedKeys = await storage.clearNamespace(WORKER_STORAGE_NAMESPACE);
    if (clearedArtifacts < 1) {
      throw new Error("expected at least one dedicated-worker artifact to be cleared");
    }
    if (clearedQuotaArtifacts < 1) {
      throw new Error("expected at least one dedicated-worker quota artifact to be cleared");
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
      exportedArtifactCount: archive.archive.artifacts.length,
      archiveFilename: archive.filename,
      downloadFailureCode,
      quotaFailureReason,
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
