/// <reference lib="webworker" />

import {
  BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE,
  createBrowserServiceWorkerBrokerStore,
  detectBrowserServiceWorkerBrokerSupport,
} from "@asupersync/browser";

declare const self: ServiceWorkerGlobalScope;

const APP_NAMESPACE = "service-worker-broker-consumer";
const APP_VERSION_MAJOR = 1;
const ARTIFACT_NAMESPACE = "service-worker-broker-artifacts";
const BROKER_PROTOCOL_VERSION = 1;
const BROKER_WORK_ID = "service-worker-broker-work-1";
const CAPABILITY_MANIFEST_VERSION = "service-worker-broker-capability-manifest-v1";
const DIRECT_EXECUTION_REASON_CODE = "service_worker_direct_runtime_not_shipped";
const IDEMPOTENCY_KEY = "service-worker-broker-idempotency-key-1";
const RUN_PROFILE = "restartable";
const SOURCE_EVENT_KIND = "message";
const STORE_NAMESPACE = "service_worker_broker_fixture";

const SERVICE_WORKER_BROKER_BOOTSTRAP_MARKER = "service-worker-broker-bootstrap";
const SERVICE_WORKER_BROKER_REGISTRATION_MARKER = "service-worker-broker-registration";
const SERVICE_WORKER_BROKER_WORK_MARKER = "service-worker-broker-work";
const SERVICE_WORKER_BROKER_HANDOFF_MARKER = "service-worker-broker-handoff";
const SERVICE_WORKER_BROKER_REOPEN_MARKER = "service-worker-broker-reopen";
const SERVICE_WORKER_BROKER_MISMATCH_MARKER = "service-worker-broker-mismatch";
const SERVICE_WORKER_BROKER_CLEANUP_MARKER = "service-worker-broker-cleanup";

type ServiceWorkerBrokerRunMessage = {
  type: "run-broker-demo";
};

type ServiceWorkerBrokerReply =
  | {
      type: "service-worker-broker-ready";
      payload: Record<string, unknown>;
    }
  | {
      type: "service-worker-broker-error";
      message: string;
    };

self.addEventListener("install", (event) => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

function postReply(
  source: ExtendableMessageEvent["source"],
  reply: ServiceWorkerBrokerReply,
): void {
  if (!source || typeof source.postMessage !== "function") {
    throw new Error("service-worker broker demo lost its reply channel");
  }
  source.postMessage(reply);
}

function supportOptions() {
  return {
    appNamespace: APP_NAMESPACE,
    appVersionMajor: APP_VERSION_MAJOR,
    brokerProtocolVersion: BROKER_PROTOCOL_VERSION,
    expectedAppNamespace: APP_NAMESPACE,
    expectedAppVersionMajor: APP_VERSION_MAJOR,
    expectedBrokerProtocolVersion: BROKER_PROTOCOL_VERSION,
    expectedRegistrationScope: self.registration.scope,
    origin: self.location.origin,
    registrationScope: self.registration.scope,
    runProfile: RUN_PROFILE,
  };
}

function summarizeSupport(support: ReturnType<typeof detectBrowserServiceWorkerBrokerSupport>) {
  return {
    marker: SERVICE_WORKER_BROKER_BOOTSTRAP_MARKER,
    supported: support.supported,
    reason: support.reason,
    runtimeContext: support.runtimeContext,
    hostRole: support.hostRole,
    requestedLane: support.requestedLane,
    fallbackLaneId: support.fallbackLaneId,
    directExecutionReasonCode: support.directExecutionReasonCode,
    message: support.message,
    guidance: [...support.guidance],
  };
}

function summarizeRegistration(
  marker: string,
  registration: NonNullable<
    Awaited<
      ReturnType<ReturnType<typeof createBrowserServiceWorkerBrokerStore>["readRegistration"]>
    >
  >,
) {
  return {
    marker,
    requestedLane: registration.requestedLane,
    fallbackLaneId: registration.fallbackLaneId,
    lifecycleState: registration.lifecycleState,
    directExecutionReasonCode: registration.directExecutionReasonCode,
    capabilityManifestVersion: registration.capabilityManifestVersion,
    registrationScope: registration.admission.registrationScope,
    appNamespace: registration.admission.appNamespace,
    registeredAtMs: registration.registeredAtMs,
    updatedAtMs: registration.updatedAtMs,
  };
}

function summarizePendingWork(
  descriptor: Awaited<
    ReturnType<ReturnType<typeof createBrowserServiceWorkerBrokerStore>["persistBrokerWork"]>
  >,
) {
  return {
    marker: SERVICE_WORKER_BROKER_WORK_MARKER,
    brokerWorkId: descriptor.brokerWorkId,
    requestedLane: descriptor.requestedLane,
    fallbackLaneId: descriptor.fallbackLaneId,
    sourceEventKind: descriptor.sourceEventKind,
    metadataMarker:
      typeof descriptor.metadata?.marker === "string" ? descriptor.metadata.marker : null,
    updatedAtMs: descriptor.updatedAtMs,
  };
}

function summarizeHandoff(
  handoff: Awaited<
    ReturnType<ReturnType<typeof createBrowserServiceWorkerBrokerStore>["persistDurableHandoff"]>
  >,
) {
  return {
    marker: SERVICE_WORKER_BROKER_HANDOFF_MARKER,
    brokerWorkId: handoff.brokerWorkId,
    requestedLane: handoff.requestedLane,
    fallbackLaneId: handoff.fallbackLaneId,
    targetLaneId: handoff.targetLaneId,
    reason: handoff.reason,
    sourceEventKind: handoff.sourceEventKind,
    metadataMarker: typeof handoff.metadata?.marker === "string" ? handoff.metadata.marker : null,
    recordedAtMs: handoff.recordedAtMs,
  };
}

async function runBrokerDemo(event: ExtendableMessageEvent): Promise<void> {
  const source = event.source;

  try {
    const support = detectBrowserServiceWorkerBrokerSupport(supportOptions());
    const store = createBrowserServiceWorkerBrokerStore({
      backend: "indexeddb",
      namespace: STORE_NAMESPACE,
    });

    await store.clearBrokerState();

    const admission = {
      origin: self.location.origin,
      registrationScope: self.registration.scope,
      appNamespace: APP_NAMESPACE,
      appVersionMajor: APP_VERSION_MAJOR,
      brokerProtocolVersion: BROKER_PROTOCOL_VERSION,
      runProfile: RUN_PROFILE,
    };

    const registration = await store.registerBroker({
      admission,
      capabilityManifestVersion: CAPABILITY_MANIFEST_VERSION,
      lifecycleState: "validating_scope",
    });

    await store.setLifecycleState("reconciling_durable_state");

    const descriptor = await store.persistBrokerWork({
      artifactNamespace: ARTIFACT_NAMESPACE,
      brokerWorkId: BROKER_WORK_ID,
      capabilityManifestVersion: CAPABILITY_MANIFEST_VERSION,
      idempotencyKey: IDEMPOTENCY_KEY,
      leaseEpoch: 1,
      metadata: {
        marker: SERVICE_WORKER_BROKER_WORK_MARKER,
      },
      sourceEventKind: SOURCE_EVENT_KIND,
    });

    await store.setLifecycleState("brokering");

    const handoff = await store.persistDurableHandoff({
      artifactNamespace: ARTIFACT_NAMESPACE,
      brokerWorkId: BROKER_WORK_ID,
      capabilityManifestVersion: CAPABILITY_MANIFEST_VERSION,
      idempotencyKey: IDEMPOTENCY_KEY,
      leaseEpoch: 1,
      metadata: {
        marker: SERVICE_WORKER_BROKER_HANDOFF_MARKER,
      },
      sourceEventKind: SOURCE_EVENT_KIND,
      targetLane: BROWSER_DEDICATED_WORKER_DIRECT_RUNTIME_LANE,
    });

    await store.setLifecycleState("draining");
    const quiescentRegistration = await store.setLifecycleState("quiescent");
    const pendingWork = await store.listPendingWork();
    const handoffs = await store.listDurableHandoffs();

    const reopenedStore = createBrowserServiceWorkerBrokerStore({
      backend: "indexeddb",
      namespace: STORE_NAMESPACE,
    });
    const reopenedRegistration = await reopenedStore.readRegistration();
    const reopenedPendingWork = await reopenedStore.listPendingWork();
    const reopenedHandoffs = await reopenedStore.listDurableHandoffs();

    const mismatch = detectBrowserServiceWorkerBrokerSupport({
      ...supportOptions(),
      expectedBrokerProtocolVersion: BROKER_PROTOCOL_VERSION + 1,
    });

    const clearedCount = await store.clearBrokerState();
    const postCleanupRegistration = await store.readRegistration();
    const postCleanupPendingWork = await store.listPendingWork();
    const postCleanupHandoffs = await store.listDurableHandoffs();

    postReply(source, {
      type: "service-worker-broker-ready",
      payload: {
        scenarioId: "SERVICE-WORKER-BROKER-CONSUMER",
        support: summarizeSupport(support),
        registration: summarizeRegistration(
          SERVICE_WORKER_BROKER_REGISTRATION_MARKER,
          quiescentRegistration ?? registration,
        ),
        pendingWork: pendingWork.map(summarizePendingWork),
        handoffs: handoffs.map(summarizeHandoff),
        reopened: {
          marker: SERVICE_WORKER_BROKER_REOPEN_MARKER,
          registration:
            reopenedRegistration === null
              ? null
              : summarizeRegistration(SERVICE_WORKER_BROKER_REOPEN_MARKER, reopenedRegistration),
          pendingWorkCount: reopenedPendingWork.length,
          handoffCount: reopenedHandoffs.length,
        },
        mismatch: {
          marker: SERVICE_WORKER_BROKER_MISMATCH_MARKER,
          supported: mismatch.supported,
          reason: mismatch.reason,
          fallbackLaneId: mismatch.fallbackLaneId,
          directExecutionReasonCode: mismatch.directExecutionReasonCode,
        },
        clearedCount,
        postCleanup: {
          marker: SERVICE_WORKER_BROKER_CLEANUP_MARKER,
          registrationMissing: postCleanupRegistration === null,
          pendingWorkCount: postCleanupPendingWork.length,
          handoffCount: postCleanupHandoffs.length,
        },
        directRuntimeReasonMarker: DIRECT_EXECUTION_REASON_CODE,
        serviceWorkerBrokerCleanupMarker: SERVICE_WORKER_BROKER_CLEANUP_MARKER,
      },
    });
  } catch (error) {
    postReply(source, {
      type: "service-worker-broker-error",
      message: error instanceof Error ? error.message : String(error),
    });
  }
}

self.addEventListener("message", (event) => {
  const message = event.data as ServiceWorkerBrokerRunMessage | undefined;
  if (!message || message.type !== "run-broker-demo") {
    return;
  }
  event.waitUntil(runBrokerDemo(event));
});
