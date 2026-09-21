type ServiceWorkerBrokerReadyMessage = {
  type: "service-worker-broker-ready";
  payload: Record<string, unknown>;
};

type ServiceWorkerBrokerErrorMessage = {
  type: "service-worker-broker-error";
  message: string;
};

type ServiceWorkerBrokerMessage = ServiceWorkerBrokerReadyMessage | ServiceWorkerBrokerErrorMessage;

const statusElement = document.getElementById("status");
if (!statusElement) {
  throw new Error("status element missing");
}

const state = {
  scenario_id: "SERVICE-WORKER-BROKER-CONSUMER",
  phase: "registering",
  controller_ready: false,
  registration_scope: null as string | null,
  events: [] as ServiceWorkerBrokerMessage[],
  broker_result: null as Record<string, unknown> | null,
  error_message: null as string | null,
  unregistered: false,
};

let registrationHandle: ServiceWorkerRegistration | null = null;

const render = () => {
  statusElement.textContent = JSON.stringify(state, null, 2);
};

async function waitForController(timeoutMs: number): Promise<void> {
  if (navigator.serviceWorker.controller) {
    return;
  }

  await new Promise<void>((resolve, reject) => {
    const timeout = window.setTimeout(() => {
      navigator.serviceWorker.removeEventListener("controllerchange", onControllerChange);
      reject(new Error("timed out waiting for service-worker controller"));
    }, timeoutMs);

    const onControllerChange = () => {
      window.clearTimeout(timeout);
      navigator.serviceWorker.removeEventListener("controllerchange", onControllerChange);
      resolve();
    };

    navigator.serviceWorker.addEventListener("controllerchange", onControllerChange);
  });
}

navigator.serviceWorker.addEventListener(
  "message",
  async (event: MessageEvent<ServiceWorkerBrokerMessage>) => {
    state.events.push(event.data);

    if (event.data.type === "service-worker-broker-ready") {
      state.phase = "broker_complete";
      state.broker_result = event.data.payload;
      render();
      if (registrationHandle) {
        state.unregistered = await registrationHandle.unregister();
      }
      state.phase = "cleanup_complete";
      render();
      return;
    }

    state.phase = "error";
    state.error_message = event.data.message;
    render();
  },
);

async function run(): Promise<void> {
  if (!("serviceWorker" in navigator)) {
    throw new Error("service workers are unavailable in this browser");
  }

  const serviceWorkerUrl = new URL("./service-worker.js", window.location.href);
  registrationHandle = await navigator.serviceWorker.register(serviceWorkerUrl, {
    type: "module",
  });
  state.registration_scope = registrationHandle.scope;
  await navigator.serviceWorker.ready;
  await waitForController(10_000);
  state.controller_ready = true;
  state.phase = "controller_ready";
  render();

  const controller = navigator.serviceWorker.controller;
  if (!controller) {
    throw new Error("service-worker controller missing after controllerchange");
  }

  state.phase = "running";
  render();
  controller.postMessage({
    type: "run-broker-demo",
  });
}

run().catch((error) => {
  state.phase = "error";
  state.error_message = error instanceof Error ? error.message : String(error);
  render();
});

render();
