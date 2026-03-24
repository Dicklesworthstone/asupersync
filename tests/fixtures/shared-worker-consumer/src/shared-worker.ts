/// <reference lib="webworker" />

const BROWSER_SHARED_WORKER_COORDINATOR_CONTRACT_ID =
  "wasm-shared-worker-tenancy-lifecycle-v1" as const;
const BROWSER_SHARED_WORKER_COORDINATOR_PROTOCOL =
  "asupersync.browser.shared_worker.handshake.v1" as const;

declare const self: SharedWorkerGlobalScope;

const APP_NAMESPACE = "shared-worker-consumer";
const APP_VERSION_MAJOR = 1;
const COORDINATOR_PROTOCOL_VERSION = 1;
const RUN_PROFILE = "ephemeral";
const TOPOLOGY_FEATURE = "shared-worker-coordinator-topology-snapshot";
const CRASH_FEATURE = "shared-worker-coordinator-crash-before-handshake";
const SHARED_WORKER_COORDINATOR_ATTACH_MARKER = "shared-worker-coordinator-attach";
const SHARED_WORKER_COORDINATOR_TOPOLOGY_MARKER =
  "shared-worker-coordinator-topology-snapshot";
const SHARED_WORKER_COORDINATOR_PROTOCOL_MISMATCH_MARKER =
  "shared-worker-coordinator-protocol-mismatch";
const SHARED_WORKER_COORDINATOR_CRASH_MARKER =
  "shared-worker-coordinator-crash-before-handshake";
const SHARED_WORKER_COORDINATOR_DETACH_MARKER = "shared-worker-coordinator-detach";

type FixtureHandshakeRequest = {
  type: "asupersync.browser.shared_worker.handshake.request";
  protocol: typeof BROWSER_SHARED_WORKER_COORDINATOR_PROTOCOL;
  contractId: typeof BROWSER_SHARED_WORKER_COORDINATOR_CONTRACT_ID;
  admission: {
    appNamespace: string;
    appVersionMajor: number;
    coordinatorProtocolVersion: number;
    runProfile: string;
  };
  client: {
    clientInstanceId: string;
    clientEpoch: number;
    clientKind: string;
    clientArtifactNamespace: string;
  };
  requestedFeatures: {
    required: string[];
    optional: string[];
  };
};

type FixtureHandshakeResponse = {
  type: "asupersync.browser.shared_worker.handshake.response";
  protocol: typeof BROWSER_SHARED_WORKER_COORDINATOR_PROTOCOL;
  contractId: typeof BROWSER_SHARED_WORKER_COORDINATOR_CONTRACT_ID;
  accepted: boolean;
  reason?: string;
  message?: string;
  guidance?: string[];
  coordinatorFeatures?: string[];
  coordinatorProtocolVersion?: number;
  lifecycleState?: string;
};

type FixtureDetachMessage = {
  type: "asupersync.browser.shared_worker.detach";
  protocol: typeof BROWSER_SHARED_WORKER_COORDINATOR_PROTOCOL;
  contractId: typeof BROWSER_SHARED_WORKER_COORDINATOR_CONTRACT_ID;
  clientInstanceId: string;
  clientEpoch: number;
};

type FixtureTopologySnapshotRequest = {
  type: "fixture.topology.snapshot.request";
  requestId: string;
  marker: string;
};

type FixtureTopologySnapshotResponse = {
  type: "fixture.topology.snapshot.response";
  requestId: string;
  snapshot: {
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
};

type ConnectedClient = {
  port: MessagePort;
  clientInstanceId: string;
  clientEpoch: number;
  clientKind: string;
  clientArtifactNamespace: string;
};

const connectedClients = new Map<string, ConnectedClient>();
let attachCount = 0;
let lastCoordinatorEvent = SHARED_WORKER_COORDINATOR_ATTACH_MARKER;

function allRequestedFeatures(request: FixtureHandshakeRequest): string[] {
  return [
    ...(request.requestedFeatures.required ?? []),
    ...(request.requestedFeatures.optional ?? []),
  ];
}

function clientKey(clientInstanceId: string, clientEpoch: number): string {
  return `${clientInstanceId}:${clientEpoch}`;
}

function currentLifecycleState(): string {
  return connectedClients.size === 0 ? "quiescent" : "active";
}

function workerName(): string | null {
  return typeof self.name === "string" && self.name.length > 0 ? self.name : null;
}

function acceptedFeatures(): string[] {
  return [
    TOPOLOGY_FEATURE,
    SHARED_WORKER_COORDINATOR_DETACH_MARKER,
  ];
}

function postHandshakeResponse(
  port: MessagePort,
  response: FixtureHandshakeResponse,
): void {
  port.postMessage(response);
}

function isHandshakeRequest(value: unknown): value is FixtureHandshakeRequest {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as Partial<FixtureHandshakeRequest>;
  return (
    candidate.type === "asupersync.browser.shared_worker.handshake.request"
    && candidate.protocol === BROWSER_SHARED_WORKER_COORDINATOR_PROTOCOL
    && candidate.contractId === BROWSER_SHARED_WORKER_COORDINATOR_CONTRACT_ID
  );
}

function isDetachMessage(value: unknown): value is FixtureDetachMessage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as Partial<FixtureDetachMessage>;
  return (
    candidate.type === "asupersync.browser.shared_worker.detach"
    && candidate.protocol === BROWSER_SHARED_WORKER_COORDINATOR_PROTOCOL
    && candidate.contractId === BROWSER_SHARED_WORKER_COORDINATOR_CONTRACT_ID
    && typeof candidate.clientInstanceId === "string"
    && typeof candidate.clientEpoch === "number"
  );
}

function isTopologySnapshotRequest(
  value: unknown,
): value is FixtureTopologySnapshotRequest {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as Partial<FixtureTopologySnapshotRequest>;
  return (
    candidate.type === "fixture.topology.snapshot.request"
    && typeof candidate.requestId === "string"
  );
}

function handleHandshake(port: MessagePort, request: FixtureHandshakeRequest): void {
  const requestedFeatures = allRequestedFeatures(request);
  if (requestedFeatures.includes(CRASH_FEATURE)) {
    lastCoordinatorEvent = SHARED_WORKER_COORDINATOR_CRASH_MARKER;
    port.close();
    self.close();
    return;
  }

  if (request.admission.appNamespace !== APP_NAMESPACE) {
    postHandshakeResponse(port, {
      type: "asupersync.browser.shared_worker.handshake.response",
      protocol: BROWSER_SHARED_WORKER_COORDINATOR_PROTOCOL,
      contractId: BROWSER_SHARED_WORKER_COORDINATOR_CONTRACT_ID,
      accepted: false,
      reason: "app_namespace_mismatch",
      message: "shared-worker coordinator rejected an unexpected app namespace",
      guidance: [
        "Keep the coordinator scoped to one app namespace per worker name.",
      ],
      coordinatorProtocolVersion: COORDINATOR_PROTOCOL_VERSION,
      lifecycleState: currentLifecycleState(),
    });
    return;
  }

  if (request.admission.appVersionMajor !== APP_VERSION_MAJOR) {
    postHandshakeResponse(port, {
      type: "asupersync.browser.shared_worker.handshake.response",
      protocol: BROWSER_SHARED_WORKER_COORDINATOR_PROTOCOL,
      contractId: BROWSER_SHARED_WORKER_COORDINATOR_CONTRACT_ID,
      accepted: false,
      reason: "app_version_major_mismatch",
      message: "shared-worker coordinator rejected an unexpected app version",
      guidance: [
        "Treat app_version_major drift as a restart boundary instead of attaching.",
      ],
      coordinatorProtocolVersion: COORDINATOR_PROTOCOL_VERSION,
      lifecycleState: currentLifecycleState(),
    });
    return;
  }

  if (
    request.admission.coordinatorProtocolVersion !== COORDINATOR_PROTOCOL_VERSION
  ) {
    lastCoordinatorEvent = SHARED_WORKER_COORDINATOR_PROTOCOL_MISMATCH_MARKER;
    postHandshakeResponse(port, {
      type: "asupersync.browser.shared_worker.handshake.response",
      protocol: BROWSER_SHARED_WORKER_COORDINATOR_PROTOCOL,
      contractId: BROWSER_SHARED_WORKER_COORDINATOR_CONTRACT_ID,
      accepted: false,
      reason: "coordinator_protocol_version_mismatch",
      message: SHARED_WORKER_COORDINATOR_PROTOCOL_MISMATCH_MARKER,
      guidance: [
        "Keep coordinator_protocol_version exact across both sides of the attach contract.",
      ],
      coordinatorProtocolVersion: COORDINATOR_PROTOCOL_VERSION,
      lifecycleState: currentLifecycleState(),
    });
    return;
  }

  if (request.admission.runProfile !== RUN_PROFILE) {
    postHandshakeResponse(port, {
      type: "asupersync.browser.shared_worker.handshake.response",
      protocol: BROWSER_SHARED_WORKER_COORDINATOR_PROTOCOL,
      contractId: BROWSER_SHARED_WORKER_COORDINATOR_CONTRACT_ID,
      accepted: false,
      reason: "registration_schema_mismatch",
      message: "shared-worker coordinator rejected an unexpected run profile",
      guidance: [
        "Keep the run_profile aligned between the caller and coordinator.",
      ],
      coordinatorProtocolVersion: COORDINATOR_PROTOCOL_VERSION,
      lifecycleState: currentLifecycleState(),
    });
    return;
  }

  const key = clientKey(request.client.clientInstanceId, request.client.clientEpoch);
  connectedClients.set(key, {
    port,
    clientInstanceId: request.client.clientInstanceId,
    clientEpoch: request.client.clientEpoch,
    clientKind: request.client.clientKind,
    clientArtifactNamespace: request.client.clientArtifactNamespace,
  });
  attachCount += 1;
  lastCoordinatorEvent = SHARED_WORKER_COORDINATOR_ATTACH_MARKER;

  postHandshakeResponse(port, {
    type: "asupersync.browser.shared_worker.handshake.response",
    protocol: BROWSER_SHARED_WORKER_COORDINATOR_PROTOCOL,
    contractId: BROWSER_SHARED_WORKER_COORDINATOR_CONTRACT_ID,
    accepted: true,
    message: SHARED_WORKER_COORDINATOR_ATTACH_MARKER,
    coordinatorFeatures: acceptedFeatures(),
    coordinatorProtocolVersion: COORDINATOR_PROTOCOL_VERSION,
    lifecycleState: currentLifecycleState(),
  });
}

function handleDetach(message: FixtureDetachMessage): void {
  connectedClients.delete(
    clientKey(message.clientInstanceId, message.clientEpoch),
  );
  lastCoordinatorEvent = SHARED_WORKER_COORDINATOR_DETACH_MARKER;
}

function handleTopologySnapshot(
  port: MessagePort,
  request: FixtureTopologySnapshotRequest,
): void {
  const response: FixtureTopologySnapshotResponse = {
    type: "fixture.topology.snapshot.response",
    requestId: request.requestId,
    snapshot: {
      marker: SHARED_WORKER_COORDINATOR_TOPOLOGY_MARKER,
      workerName: workerName(),
      lifecycleState: currentLifecycleState(),
      clientCount: connectedClients.size,
      attachCount,
      clientIds: Array.from(connectedClients.values()).map(
        (client) => client.clientInstanceId,
      ),
      protocolVersion: COORDINATOR_PROTOCOL_VERSION,
      appNamespace: APP_NAMESPACE,
      appVersionMajor: APP_VERSION_MAJOR,
      runProfile: RUN_PROFILE,
      lastCoordinatorEvent,
    },
  };
  port.postMessage(response);
}

self.addEventListener("connect", (event: Event) => {
  const connectEvent = event as MessageEvent;
  const port = connectEvent.ports[0];
  if (!port) {
    return;
  }

  port.addEventListener("message", (messageEvent: MessageEvent<unknown>) => {
    const { data } = messageEvent;
    if (isHandshakeRequest(data)) {
      handleHandshake(port, data);
      return;
    }
    if (isDetachMessage(data)) {
      handleDetach(data);
      return;
    }
    if (isTopologySnapshotRequest(data)) {
      handleTopologySnapshot(port, data);
    }
  });

  port.start();
});
