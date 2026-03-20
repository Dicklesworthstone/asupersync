type WorkerBootstrapPayload = {
  scenarioId: string;
};

type WorkerBootstrapMessage = {
  type: "worker-bootstrap";
  payload: WorkerBootstrapPayload & Record<string, unknown>;
};

type WorkerBootstrapFailedMessage = {
  type: "worker-bootstrap-failed";
  message: string;
};

type WorkerShutdownMessage = {
  type: "worker-shutdown-complete";
  reason: string | null;
};

type WorkerMessage =
  | WorkerBootstrapMessage
  | WorkerBootstrapFailedMessage
  | WorkerShutdownMessage;

const statusElement = document.getElementById("status");
if (!statusElement) {
  throw new Error("status element missing");
}

const worker = new Worker(new URL("./worker.ts", import.meta.url), {
  type: "module",
});

const state = {
  scenario_id: "DEDICATED-WORKER-CONSUMER",
  phase: "spawning",
  events: [] as WorkerMessage[],
  worker_bootstrap: null as WorkerBootstrapMessage["payload"] | null,
  shutdown_reason: null as string | null,
  error_message: null as string | null,
};

const render = () => {
  statusElement.textContent = JSON.stringify(
    state,
    (_key, value) => (typeof value === "bigint" ? value.toString() : value),
    2,
  );
};

worker.addEventListener("message", (event: MessageEvent<WorkerMessage>) => {
  state.events.push(event.data);

  if (event.data.type === "worker-bootstrap") {
    state.phase = "worker_ready";
    state.worker_bootstrap = event.data.payload;
    render();
    worker.postMessage({
      type: "shutdown",
      reason: "fixture-handoff-complete",
    });
    return;
  }

  if (event.data.type === "worker-shutdown-complete") {
    state.phase = "shutdown_complete";
    state.shutdown_reason = event.data.reason;
    render();
    worker.terminate();
    return;
  }

  state.phase = "worker_error";
  state.error_message = event.data.message;
  render();
});

worker.addEventListener("error", (event) => {
  state.phase = "worker_error";
  state.error_message = event.message || "worker bootstrap failed";
  state.events.push({
    type: "worker-bootstrap-failed",
    message: event.message || "worker bootstrap failed",
  });
  render();
});

render();
