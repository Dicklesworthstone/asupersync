import init, {
  inspect_rust_browser_execution_ladder,
  inspect_rust_browser_execution_ladder_preferred_dedicated_worker,
  run_rust_browser_consumer_demo,
  select_rust_browser_runtime,
  select_rust_browser_runtime_preferred_dedicated_worker,
} from "../pkg/asupersync_rust_browser_consumer_fixture.js";

const statusElement = document.getElementById("status");
if (!statusElement) {
  throw new Error("status element missing");
}

const MAIN_THREAD_MATRIX_MARKER = "rust-browser-main-thread-matrix";
const DEDICATED_WORKER_MATRIX_MARKER = "rust-browser-dedicated-worker-matrix";
const DOWNGRADE_MARKER = "rust-browser-downgrade-missing-webassembly";
const WORKER_READY_TYPE = "rust-browser-worker-ready";
const WORKER_ERROR_TYPE = "rust-browser-worker-error";

const render = (value: unknown): void => {
  statusElement.textContent = JSON.stringify(value, null, 2);
};

async function withDeletedGlobalProperty<T>(
  key: string,
  operation: () => Promise<T> | T,
): Promise<{
  simulated: boolean;
  skipped_reason: string | null;
  value: T | null;
}> {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, key);
  if (!descriptor) {
    return {
      simulated: false,
      skipped_reason: `${key} descriptor is missing`,
      value: null,
    };
  }
  if (!descriptor.configurable) {
    return {
      simulated: false,
      skipped_reason: `${key} is not configurable on globalThis`,
      value: null,
    };
  }
  if (!Reflect.deleteProperty(globalThis, key)) {
    return {
      simulated: false,
      skipped_reason: `Reflect.deleteProperty(globalThis, ${key}) returned false`,
      value: null,
    };
  }

  try {
    return {
      simulated: true,
      skipped_reason: null,
      value: await operation(),
    };
  } finally {
    Object.defineProperty(globalThis, key, descriptor);
  }
}

async function collectDedicatedWorkerMatrix(): Promise<Record<string, unknown>> {
  const worker = new Worker(new URL("./worker.ts", import.meta.url), {
    type: "module",
  });

  return await new Promise<Record<string, unknown>>((resolve, reject) => {
    const timeout = window.setTimeout(() => {
      worker.terminate();
      reject(new Error("timed out waiting for dedicated worker matrix"));
    }, 15_000);

    const cleanup = (): void => {
      window.clearTimeout(timeout);
      worker.terminate();
    };

    worker.addEventListener("message", (event: MessageEvent<Record<string, unknown>>) => {
      const payload = event.data;
      if (payload?.type === WORKER_READY_TYPE) {
        cleanup();
        resolve({
          marker: DEDICATED_WORKER_MATRIX_MARKER,
          ...(payload.payload as Record<string, unknown>),
        });
        return;
      }

      if (payload?.type === WORKER_ERROR_TYPE) {
        cleanup();
        reject(new Error(String(payload.message ?? "worker reported an unknown error")));
      }
    });

    worker.addEventListener("error", (event) => {
      cleanup();
      reject(event.error instanceof Error ? event.error : new Error(event.message));
    });
  });
}

async function main(): Promise<void> {
  render({
    phase: "initializing",
    scenario: "rust-browser-consumer",
  });

  await init();
  const lifecycle = run_rust_browser_consumer_demo() as Record<string, unknown>;
  const ladder = inspect_rust_browser_execution_ladder() as Record<string, unknown>;
  const preferredDedicatedWorker =
    inspect_rust_browser_execution_ladder_preferred_dedicated_worker() as Record<string, unknown>;
  const browserSelection = select_rust_browser_runtime() as Record<string, unknown>;
  const preferredDedicatedWorkerBrowserSelection =
    select_rust_browser_runtime_preferred_dedicated_worker() as Record<string, unknown>;
  const dedicatedWorker = await collectDedicatedWorkerMatrix();
  const downgradeWithoutWebAssembly = await withDeletedGlobalProperty("WebAssembly", () => ({
    ladder: inspect_rust_browser_execution_ladder() as Record<string, unknown>,
    browser_selection: select_rust_browser_runtime() as Record<string, unknown>,
  }));

  const dedicatedWorkerLadder = dedicatedWorker.ladder as Record<string, unknown>;
  const dedicatedWorkerCapabilities = dedicatedWorkerLadder.capabilities as Record<
    string,
    Record<string, unknown>
  >;
  const mainThreadCapabilities = ladder.capabilities as Record<string, Record<string, unknown>>;

  const summary = {
    scenario_id: "RUST-BROWSER-CONSUMER",
    support_lane: "repository_maintained_rust_browser_fixture",
    harness_mode: "matrix",
    matrix_version: 2,
    ready_phase: lifecycle.ready_phase,
    disposed_phase: lifecycle.disposed_phase,
    child_scope_count_before_unmount: lifecycle.child_scope_count_before_unmount,
    active_task_count_before_unmount: lifecycle.active_task_count_before_unmount,
    completed_task_outcome: lifecycle.completed_task_outcome,
    cancel_event_count: lifecycle.cancel_event_count,
    dispatch_count: lifecycle.dispatch_count,
    event_symbols: lifecycle.event_symbols,
    capabilities: lifecycle.capabilities,
    main_thread: {
      marker: MAIN_THREAD_MATRIX_MARKER,
      lifecycle,
      ladder,
      browser_selection: browserSelection,
      preferred_dedicated_worker: preferredDedicatedWorker,
      preferred_dedicated_worker_browser_selection:
        preferredDedicatedWorkerBrowserSelection,
      downgrade_without_webassembly: downgradeWithoutWebAssembly.value?.ladder ?? null,
      downgrade_browser_selection:
        downgradeWithoutWebAssembly.value?.browser_selection ?? null,
      downgrade_simulation: {
        marker: DOWNGRADE_MARKER,
        simulated: downgradeWithoutWebAssembly.simulated,
        skipped_reason: downgradeWithoutWebAssembly.skipped_reason,
      },
    },
    dedicated_worker: dedicatedWorker,
    guarded_capabilities: {
      main_thread_local_storage:
        mainThreadCapabilities.storage?.has_local_storage === true,
      main_thread_indexed_db: mainThreadCapabilities.storage?.has_indexed_db === true,
      main_thread_web_transport:
        mainThreadCapabilities.transport?.has_web_transport === true,
      dedicated_worker_local_storage:
        dedicatedWorkerCapabilities.storage?.has_local_storage === true,
      dedicated_worker_indexed_db:
        dedicatedWorkerCapabilities.storage?.has_indexed_db === true,
      dedicated_worker_web_transport:
        dedicatedWorkerCapabilities.transport?.has_web_transport === true,
    },
  };
  render(summary);
}

void main().catch((error) => {
  render({
    phase: "error",
    message:
      error instanceof Error ? error.message : typeof error === "string" ? error : "unknown error",
  });
});
