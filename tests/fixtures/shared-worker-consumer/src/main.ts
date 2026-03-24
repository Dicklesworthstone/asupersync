import {
  createBrowserSharedWorkerCoordinatorSelection,
  detectBrowserSharedWorkerCoordinatorSupport,
  type BrowserSharedWorkerCoordinatorAttachDiagnostics,
  type BrowserSharedWorkerCoordinatorSelectionResult,
  type BrowserRuntimeSelectionResult,
} from "@asupersync/browser";
import SharedWorkerFixture from "./shared-worker.ts?sharedworker";

const APP_NAMESPACE = "shared-worker-consumer";
const APP_VERSION_MAJOR = 1;
const COORDINATOR_PROTOCOL_VERSION = 1;
const RUN_PROFILE = "ephemeral";
const TOPOLOGY_FEATURE = "shared-worker-coordinator-topology-snapshot";
const CRASH_FEATURE = "shared-worker-coordinator-crash-before-handshake";
const SHARED_WORKER_SELECTION_BASELINE_MARKER = "shared-worker-selection-baseline";
const SHARED_WORKER_SELECTION_REUSE_MARKER = "shared-worker-selection-reuse";
const SHARED_WORKER_SELECTION_PROTOCOL_MISMATCH_MARKER =
  "shared-worker-selection-protocol-mismatch";
const SHARED_WORKER_SELECTION_CRASH_FALLBACK_MARKER =
  "shared-worker-selection-crash-fallback";

type FixtureTopologySnapshot = {
  marker: string;
  workerName: string | null;
  lifecycleState: string;
  clientCount: number;
  attachCount: number;
  clientIds: string[];
  protocolVersion: number;
  appNamespace: string;
  appVersionMajor: number;
  runProfile: string;
  lastCoordinatorEvent: string;
};

type FixtureTopologySnapshotResponse = {
  type: "fixture.topology.snapshot.response";
  requestId: string;
  snapshot: FixtureTopologySnapshot;
};

const statusElement = document.getElementById("status");
if (!statusElement) {
  throw new Error("status element missing");
}

const params = new URLSearchParams(window.location.search);
const clientId = params.get("clientId") ?? "page-a";
const pageScenario = params.get("scenario") ?? "shared-worker-baseline";
const expectedClients = Math.max(
  1,
  Number.parseInt(params.get("expectedClients") ?? "1", 10) || 1,
);
const workerName = params.get("workerName") ?? "asupersync-shared-worker-fixture";
const requestedCoordinatorProtocolVersion = Math.max(
  1,
  Number.parseInt(
    params.get("coordinatorProtocolVersion")
      ?? String(COORDINATOR_PROTOCOL_VERSION),
    10,
  ) || COORDINATOR_PROTOCOL_VERSION,
);
const handshakeTimeoutMs = Math.max(
  50,
  Number.parseInt(params.get("handshakeTimeoutMs") ?? "1000", 10) || 1000,
);
const forceCrashBeforeHandshake = params.get("forceCrashBeforeHandshake") === "1";

const state = {
  scenario_id: "SHARED-WORKER-CONSUMER",
  client_id: clientId,
  page_scenario: pageScenario,
  phase: "bootstrapping",
  expected_clients: expectedClients,
  support: null as Record<string, unknown> | null,
  selection: null as Record<string, unknown> | null,
  attach: null as Record<string, unknown> | null,
  topology_snapshot: null as FixtureTopologySnapshot | null,
  fallback_runtime: null as Record<string, unknown> | null,
  close_lifecycle_state: null as string | null,
  events: [] as string[],
  error_message: null as string | null,
};

let capturedPort: MessagePort | null = null;
let selectionHandle: BrowserSharedWorkerCoordinatorSelectionResult | null = null;

const render = () => {
  statusElement.textContent = JSON.stringify(state, null, 2);
};

function summarizeOutcome(
  outcome: BrowserRuntimeSelectionResult["outcome"] | null,
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

function summarizeSupport(
  support: ReturnType<typeof detectBrowserSharedWorkerCoordinatorSupport>,
): Record<string, unknown> {
  return {
    supported: support.supported,
    contractId: support.contractId,
    requestedLane: support.requestedLane,
    fallbackTarget: support.fallbackTarget,
    fallbackLaneId: support.fallbackLaneId,
    hostRole: support.hostRole,
    runtimeContext: support.runtimeContext,
    reason: support.reason,
    message: support.message,
    directExecutionReasonCode: support.directExecutionReasonCode,
    appNamespace: support.appNamespace,
    appVersionMajor: support.appVersionMajor,
    coordinatorProtocolVersion: support.coordinatorProtocolVersion,
    workerName: support.workerName,
  };
}

function summarizeSelection(
  selection: BrowserSharedWorkerCoordinatorSelectionResult,
): Record<string, unknown> {
  return {
    selectedMode: selection.selectedMode,
    reason: selection.reason,
    message: selection.message,
    fallbackTarget: selection.fallbackTarget,
    fallbackLaneId: selection.fallbackLaneId,
    executionLadder: {
      supported: selection.executionLadder.supported,
      selectedLane: selection.executionLadder.selectedLane,
      preferredLane: selection.executionLadder.preferredLane,
      reasonCode: selection.executionLadder.reasonCode,
      hostRole: selection.executionLadder.hostRole,
      runtimeContext: selection.executionLadder.runtimeContext,
      healthStatus: selection.executionLadder.health.status,
    },
  };
}

function summarizeAttach(
  diagnostics: BrowserSharedWorkerCoordinatorAttachDiagnostics,
): Record<string, unknown> {
  return {
    contractId: diagnostics.contractId,
    requestedLane: diagnostics.requestedLane,
    fallbackTarget: diagnostics.fallbackTarget,
    fallbackLaneId: diagnostics.fallbackLaneId,
    lifecycleState: diagnostics.lifecycleState,
    coordinatorFeatures: diagnostics.coordinatorFeatures,
    scriptUrl: diagnostics.scriptUrl,
    workerName: diagnostics.workerName,
    admission: diagnostics.admission,
    client: diagnostics.client,
    directExecutionLadder: {
      supported: diagnostics.directExecutionLadder.supported,
      selectedLane: diagnostics.directExecutionLadder.selectedLane,
      preferredLane: diagnostics.directExecutionLadder.preferredLane,
      reasonCode: diagnostics.directExecutionLadder.reasonCode,
      hostRole: diagnostics.directExecutionLadder.hostRole,
      runtimeContext: diagnostics.directExecutionLadder.runtimeContext,
    },
  };
}

function summarizeRuntimeSelection(
  selection: BrowserRuntimeSelectionResult | null,
): Record<string, unknown> | null {
  if (!selection) {
    return null;
  }
  const outcome = summarizeOutcome(selection.outcome);
  return {
    executionLadder: {
      supported: selection.executionLadder.supported,
      selectedLane: selection.executionLadder.selectedLane,
      preferredLane: selection.executionLadder.preferredLane,
      reasonCode: selection.executionLadder.reasonCode,
      hostRole: selection.executionLadder.hostRole,
      runtimeContext: selection.executionLadder.runtimeContext,
      healthStatus: selection.executionLadder.health.status,
    },
    runtimePresent: selection.runtime !== null,
    outcome: outcome.outcome,
    failureCode: outcome.failureCode,
    failureMessage: outcome.failureMessage,
  };
}

function closeFallbackRuntime(selection: BrowserRuntimeSelectionResult | null): void {
  selection?.runtime?.close();
}

function isTopologySnapshotResponse(
  value: unknown,
): value is FixtureTopologySnapshotResponse {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as Partial<FixtureTopologySnapshotResponse>;
  return (
    candidate.type === "fixture.topology.snapshot.response"
    && typeof candidate.requestId === "string"
    && typeof candidate.snapshot === "object"
    && candidate.snapshot !== null
  );
}

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

let snapshotSequence = 0;

async function requestSingleTopologySnapshot(
  port: MessagePort,
  selection: BrowserSharedWorkerCoordinatorSelectionResult,
  timeoutMs: number,
): Promise<FixtureTopologySnapshot> {
  const coordinator = selection.coordinator;
  if (!coordinator) {
    throw new Error("SharedWorker coordinator handle missing");
  }

  const requestId = `${clientId}-${snapshotSequence}`;
  snapshotSequence += 1;

  return new Promise((resolve, reject) => {
    const timer = window.setTimeout(() => {
      cleanup();
      reject(
        new Error(
          `timed out waiting for topology snapshot after ${timeoutMs}ms`,
        ),
      );
    }, timeoutMs);

    const cleanup = () => {
      window.clearTimeout(timer);
      port.removeEventListener("message", onMessage);
      port.removeEventListener("messageerror", onMessageError);
    };

    const onMessage = (event: MessageEvent<unknown>) => {
      if (!isTopologySnapshotResponse(event.data)) {
        return;
      }
      if (event.data.requestId !== requestId) {
        return;
      }
      cleanup();
      resolve(event.data.snapshot);
    };

    const onMessageError = () => {
      cleanup();
      reject(new Error("topology snapshot response was not decodable"));
    };

    port.addEventListener("message", onMessage);
    port.addEventListener("messageerror", onMessageError);
    port.start?.();

    coordinator.postMessage({
      type: "fixture.topology.snapshot.request",
      requestId,
      marker: TOPOLOGY_FEATURE,
    });
  });
}

async function waitForExpectedTopology(
  port: MessagePort,
  selection: BrowserSharedWorkerCoordinatorSelectionResult,
  expectedCount: number,
  timeoutMs: number,
): Promise<FixtureTopologySnapshot> {
  const deadline = Date.now() + timeoutMs;
  let lastSnapshot: FixtureTopologySnapshot | null = null;

  while (Date.now() < deadline) {
    const remaining = Math.max(100, deadline - Date.now());
    lastSnapshot = await requestSingleTopologySnapshot(
      port,
      selection,
      Math.min(remaining, 1000),
    );
    if (lastSnapshot.clientCount >= expectedCount) {
      return lastSnapshot;
    }
    await wait(100);
  }

  throw new Error(
    `expected topology snapshot with at least ${expectedCount} clients, got ${lastSnapshot?.clientCount ?? 0}`,
  );
}

async function run(): Promise<void> {
  const workerFactory = (_scriptUrl: string, resolvedWorkerName: string | null) => {
    const worker =
      resolvedWorkerName === null
        ? new SharedWorkerFixture()
        : new SharedWorkerFixture({ name: resolvedWorkerName });
    worker.addEventListener("error", (event) => {
      state.events.push(
        `shared-worker-factory-error:${event.message || "unknown-worker-error"}`,
      );
      render();
    });
    capturedPort = worker.port;
    return worker;
  };

  const support = detectBrowserSharedWorkerCoordinatorSupport({
    appNamespace: APP_NAMESPACE,
    appVersionMajor: APP_VERSION_MAJOR,
    coordinatorProtocolVersion: requestedCoordinatorProtocolVersion,
    runProfile: RUN_PROFILE,
    workerFactory,
    workerName,
  });
  state.support = summarizeSupport(support);
  render();

  selectionHandle = await createBrowserSharedWorkerCoordinatorSelection({
    appNamespace: APP_NAMESPACE,
    appVersionMajor: APP_VERSION_MAJOR,
    coordinatorProtocolVersion: requestedCoordinatorProtocolVersion,
    runProfile: RUN_PROFILE,
    workerName,
    workerFactory,
    clientArtifactNamespace: `shared-worker-artifacts-${clientId}`,
    clientCapabilitySummary: {
      pageScenario,
      clientId,
      expectedClients,
    },
    clientInstanceId: clientId,
    clientKind: "browser_page",
    clientStartedAtMs: Date.now(),
    handshakeTimeoutMs,
    requiredCoordinatorFeatures: [TOPOLOGY_FEATURE],
    optionalCoordinatorFeatures: forceCrashBeforeHandshake ? [CRASH_FEATURE] : [],
  });

  state.selection = summarizeSelection(selectionHandle);
  render();

  if (selectionHandle.selectedMode === "fallback") {
    state.fallback_runtime = summarizeRuntimeSelection(
      selectionHandle.runtimeSelection,
    );
    if (selectionHandle.reason === "coordinator_protocol_version_mismatch") {
      state.events.push(SHARED_WORKER_SELECTION_PROTOCOL_MISMATCH_MARKER);
    }
    if (
      forceCrashBeforeHandshake
      && selectionHandle.reason === "coordinator_bootstrap_failure"
    ) {
      state.events.push(SHARED_WORKER_SELECTION_CRASH_FALLBACK_MARKER);
    }
    state.phase = "fallback_complete";
    closeFallbackRuntime(selectionHandle.runtimeSelection);
    render();
    return;
  }

  const coordinator = selectionHandle.coordinator;
  if (!coordinator || capturedPort === null) {
    throw new Error("expected SharedWorker coordinator selection to expose a port");
  }

  state.events.push(SHARED_WORKER_SELECTION_BASELINE_MARKER);
  state.attach = summarizeAttach(coordinator.diagnostics());
  state.phase = expectedClients > 1 ? "awaiting_reuse" : "awaiting_topology";
  render();

  const topologySnapshot = await waitForExpectedTopology(
    capturedPort,
    selectionHandle,
    expectedClients,
    10_000,
  );
  state.topology_snapshot = topologySnapshot;
  if (expectedClients > 1) {
    state.events.push(SHARED_WORKER_SELECTION_REUSE_MARKER);
  }
  state.phase = "shared_worker_complete";
  render();

  await wait(750);
  coordinator.close();
  state.close_lifecycle_state = coordinator.diagnostics().lifecycleState;
  state.phase = "closed";
  render();
}

run().catch((error) => {
  state.phase = "error";
  state.error_message = error instanceof Error ? error.message : String(error);
  render();
  if (selectionHandle?.selectedMode === "shared_worker") {
    selectionHandle.coordinator?.close();
  } else if (selectionHandle !== null) {
    closeFallbackRuntime(selectionHandle.runtimeSelection);
  }
});

render();
