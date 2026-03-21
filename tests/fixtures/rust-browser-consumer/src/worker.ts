/// <reference lib="webworker" />

import init, {
  inspect_rust_browser_execution_ladder,
  inspect_rust_browser_execution_ladder_preferred_main_thread,
  run_rust_browser_consumer_demo,
} from "../pkg/asupersync_rust_browser_consumer_fixture.js";

declare const self: DedicatedWorkerGlobalScope;

const WORKER_READY_TYPE = "rust-browser-worker-ready";
const WORKER_ERROR_TYPE = "rust-browser-worker-error";
const WORKER_BOOTSTRAP_MARKER = "rust-browser-worker-bootstrap";

async function bootstrap(): Promise<void> {
  await init();

  const lifecycle = run_rust_browser_consumer_demo() as Record<string, unknown>;
  const ladder = inspect_rust_browser_execution_ladder() as Record<string, unknown>;
  const preferredMainThread =
    inspect_rust_browser_execution_ladder_preferred_main_thread() as Record<
      string,
      unknown
    >;

  self.postMessage({
    type: WORKER_READY_TYPE,
    payload: {
      bootstrap_marker: WORKER_BOOTSTRAP_MARKER,
      lifecycle,
      ladder,
      preferred_main_thread: preferredMainThread,
    },
  });
}

void bootstrap().catch((error) => {
  self.postMessage({
    type: WORKER_ERROR_TYPE,
    message:
      error instanceof Error ? error.message : typeof error === "string" ? error : "unknown error",
  });
});
