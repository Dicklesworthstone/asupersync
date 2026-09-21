import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { chromium } from "playwright-core";

const distDir = path.resolve("dist");
const outputPath = process.argv[2] ? path.resolve(process.argv[2]) : null;
const REQUIRED_EVENT_SYMBOLS = ["task_spawn", "task_join", "task_cancel"];
const MAIN_THREAD_LANE = "lane.browser.main_thread.direct_runtime";
const DEDICATED_WORKER_LANE = "lane.browser.dedicated_worker.direct_runtime";
const UNSUPPORTED_LANE = "lane.unsupported";

function detectChromiumExecutable() {
  const explicit = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH;
  if (explicit) {
    return explicit;
  }
  for (const candidate of [
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
  ]) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  throw new Error(
    "No Chromium executable found. Set PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH to a Chrome/Chromium binary.",
  );
}

function contentTypeFor(filePath) {
  switch (path.extname(filePath)) {
    case ".html":
      return "text/html; charset=utf-8";
    case ".js":
    case ".mjs":
      return "text/javascript; charset=utf-8";
    case ".css":
      return "text/css; charset=utf-8";
    case ".wasm":
      return "application/wasm";
    case ".json":
      return "application/json; charset=utf-8";
    default:
      return "application/octet-stream";
  }
}

function resolveRequestPath(urlPathname) {
  const normalized = decodeURIComponent(urlPathname === "/" ? "/index.html" : urlPathname);
  const resolved = path.resolve(distDir, `.${normalized}`);
  const relative = path.relative(distDir, resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(`refusing to serve path outside dist: ${urlPathname}`);
  }
  return resolved;
}

function writeResult(result) {
  if (!outputPath) {
    return;
  }
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, JSON.stringify(result, null, 2) + "\n");
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function assertLifecycle(label, lifecycle, expectedCapabilities) {
  assert(
    lifecycle?.support_lane === "repository_maintained_rust_browser_fixture",
    `${label} must preserve the repository-maintained support lane`,
  );
  assert(lifecycle?.diagnostics_clean === true, `${label} diagnostics must stay clean`);
  assert(lifecycle?.ready_phase === "ready", `${label} must reach ready phase`);
  assert(lifecycle?.disposed_phase === "disposed", `${label} must reach disposed phase`);
  assert(
    lifecycle?.child_scope_count_before_unmount === 1,
    `${label} must create exactly one child scope before unmount`,
  );
  assert(
    lifecycle?.active_task_count_before_unmount === 1,
    `${label} must retain exactly one active task before unmount`,
  );
  assert(
    lifecycle?.completed_task_outcome === "ok",
    `${label} completed task must resolve with ok`,
  );
  assert(lifecycle?.cancel_event_count === 1, `${label} must emit exactly one cancellation event`);
  assert(
    Number.isInteger(lifecycle?.dispatch_count) && lifecycle.dispatch_count >= 6,
    `${label} dispatch count must stay >= 6`,
  );
  assert(Array.isArray(lifecycle?.event_symbols), `${label} event_symbols must be an array`);
  for (const symbol of REQUIRED_EVENT_SYMBOLS) {
    assert(
      lifecycle.event_symbols.includes(symbol),
      `${label} event log missing required symbol: ${symbol}`,
    );
  }
  assert(
    lifecycle?.capabilities?.has_window === expectedCapabilities.has_window,
    `${label} window capability drifted`,
  );
  assert(
    lifecycle?.capabilities?.has_document === expectedCapabilities.has_document,
    `${label} document capability drifted`,
  );
  assert(
    lifecycle?.capabilities?.has_webassembly === expectedCapabilities.has_webassembly,
    `${label} WebAssembly capability drifted`,
  );
}

function assertLadder(label, ladder, expected) {
  assert(ladder?.supported === expected.supported, `${label} supported flag drifted`);
  assert(
    ladder?.selected_lane === expected.selected_lane,
    `${label} selected unexpected lane: ${ladder?.selected_lane ?? "missing"}`,
  );
  assert(
    ladder?.host_role === expected.host_role,
    `${label} host role drifted: ${ladder?.host_role ?? "missing"}`,
  );
  assert(
    ladder?.runtime_context === expected.runtime_context,
    `${label} runtime context drifted: ${ladder?.runtime_context ?? "missing"}`,
  );
  assert(
    ladder?.support_class === expected.support_class,
    `${label} support class drifted: ${ladder?.support_class ?? "missing"}`,
  );
  assert(
    ladder?.reason_code === expected.reason_code,
    `${label} reason code drifted: ${ladder?.reason_code ?? "missing"}`,
  );
  assert(Array.isArray(ladder?.candidates), `${label} candidates must remain an array`);
}

function assertCandidateReason(label, ladder, laneId, reasonCode) {
  const candidate = Array.isArray(ladder?.candidates)
    ? ladder.candidates.find((value) => value.lane_id === laneId)
    : undefined;
  assert(candidate, `${label} missing candidate ${laneId}`);
  assert(
    candidate.reason_code === reasonCode,
    `${label} candidate ${laneId} expected reason ${reasonCode}, got ${candidate.reason_code ?? "missing"}`,
  );
}

function assertBrowserSelection(label, selection, expected) {
  assert(selection?.supported === expected.supported, `${label} supported flag drifted`);
  assert(
    selection?.selected_lane === expected.selected_lane,
    `${label} selected unexpected lane: ${selection?.selected_lane ?? "missing"}`,
  );
  assert(
    selection?.reason_code === expected.reason_code,
    `${label} reason code drifted: ${selection?.reason_code ?? "missing"}`,
  );
  assert(
    selection?.runtime_available === expected.runtime_available,
    `${label} runtime availability drifted`,
  );
  if (expected.preferred_lane !== undefined) {
    assert(
      selection?.preferred_lane === expected.preferred_lane,
      `${label} preferred lane drifted: ${selection?.preferred_lane ?? "missing"}`,
    );
  }
  if (expected.runtime_available) {
    assert(selection?.scope_close_outcome === "ok", `${label} scope close must return ok`);
    assert(selection?.runtime_close_outcome === "ok", `${label} runtime close must return ok`);
    assert(
      Number.isInteger(selection?.dispatch_count) && selection.dispatch_count >= 4,
      `${label} dispatch count must stay >= 4`,
    );
    assert(
      selection?.diagnostics_clean === true,
      `${label} dispatcher diagnostics must stay clean`,
    );
  } else {
    assert(
      selection?.dispatch_count == null,
      `${label} should not report dispatch activity when no runtime was constructed`,
    );
  }
}

function assertWorkerSupport(label, support, expected) {
  assert(support?.supported === expected.supported, `${label} supported flag drifted`);
  assert(
    support?.contract_id === expected.contract_id,
    `${label} contract id drifted: ${support?.contract_id ?? "missing"}`,
  );
  assert(
    support?.requested_lane === expected.requested_lane,
    `${label} requested lane drifted: ${support?.requested_lane ?? "missing"}`,
  );
  assert(
    support?.fallback_target === expected.fallback_target,
    `${label} fallback target drifted: ${support?.fallback_target ?? "missing"}`,
  );
  assert(
    support?.fallback_lane_id === expected.fallback_lane_id,
    `${label} fallback lane id drifted: ${support?.fallback_lane_id ?? "missing"}`,
  );
  assert(
    support?.host_role === expected.host_role,
    `${label} host role drifted: ${support?.host_role ?? "missing"}`,
  );
  assert(
    support?.runtime_context === expected.runtime_context,
    `${label} runtime context drifted: ${support?.runtime_context ?? "missing"}`,
  );
  assert(
    support?.reason === expected.reason,
    `${label} reason drifted: ${support?.reason ?? "missing"}`,
  );
  assert(
    support?.direct_runtime_reason === expected.direct_runtime_reason,
    `${label} direct runtime reason drifted: ${support?.direct_runtime_reason ?? "missing"}`,
  );
  assert(
    support?.direct_execution_reason_code === expected.direct_execution_reason_code,
    `${label} direct execution reason drifted: ${support?.direct_execution_reason_code ?? "missing"}`,
  );
  assert(Array.isArray(support?.downgrade_order), `${label} downgrade order must remain an array`);
}

function startStaticServer() {
  const server = http.createServer((request, response) => {
    try {
      const requestUrl = new URL(request.url ?? "/", "http://127.0.0.1");
      const filePath = resolveRequestPath(requestUrl.pathname);
      if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
        response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
        response.end("not found");
        return;
      }
      response.writeHead(200, { "content-type": contentTypeFor(filePath) });
      response.end(fs.readFileSync(filePath));
    } catch (error) {
      response.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
      response.end(error instanceof Error ? error.message : String(error));
    }
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("failed to resolve static server address"));
        return;
      }
      resolve({ server, port: address.port });
    });
  });
}

if (!fs.existsSync(distDir)) {
  throw new Error(`Missing dist directory: ${distDir}`);
}

const executablePath = detectChromiumExecutable();
let browser;
let serverHandle;
let url = null;
let result;
let caughtError = null;

try {
  serverHandle = await startStaticServer();
  browser = await chromium.launch({
    executablePath,
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });
  const page = await browser.newPage();
  url = `http://127.0.0.1:${serverHandle.port}/index.html`;

  await page.goto(url, { waitUntil: "domcontentloaded" });
  await page.waitForFunction(() => {
    const node = document.querySelector("#status");
    if (!node) {
      return false;
    }
    const text = node.textContent ?? "";
    if (!text || text === "loading...") {
      return false;
    }
    try {
      const parsed = JSON.parse(text);
      return parsed.scenario_id === "RUST-BROWSER-CONSUMER" || parsed.phase === "error";
    } catch {
      return false;
    }
  });

  const statusText = await page.locator("#status").textContent();
  if (!statusText) {
    throw new Error("browser run completed without status text");
  }

  const parsed = JSON.parse(statusText);
  if (parsed.phase === "error") {
    throw new Error(`fixture rendered error payload: ${parsed.message ?? "unknown error"}`);
  }
  if (parsed.scenario_id !== "RUST-BROWSER-CONSUMER") {
    throw new Error(`unexpected scenario_id: ${parsed.scenario_id ?? "missing"}`);
  }
  if (parsed.support_lane !== "repository_maintained_rust_browser_fixture") {
    throw new Error(`unexpected support lane: ${parsed.support_lane ?? "missing"}`);
  }
  assert(
    parsed.harness_mode === "matrix",
    `unexpected harness mode: ${parsed.harness_mode ?? "missing"}`,
  );
  assert(
    parsed.matrix_version === 2,
    `unexpected matrix version: ${parsed.matrix_version ?? "missing"}`,
  );

  const mainThread = parsed.main_thread;
  const dedicatedWorker = parsed.dedicated_worker;
  const mainThreadLifecycle = mainThread?.lifecycle;
  const workerLifecycle = dedicatedWorker?.lifecycle;
  const mainThreadLadder = mainThread?.ladder;
  const workerLadder = dedicatedWorker?.ladder;
  const preferredDedicatedWorker = mainThread?.preferred_dedicated_worker;
  const mainThreadBrowserSelection = mainThread?.browser_selection;
  const preferredDedicatedWorkerBrowserSelection =
    mainThread?.preferred_dedicated_worker_browser_selection;
  const preferredMainThread = dedicatedWorker?.preferred_main_thread;
  const workerBrowserSelection = dedicatedWorker?.browser_selection;
  const preferredMainThreadBrowserSelection =
    dedicatedWorker?.preferred_main_thread_browser_selection;
  const downgrade = mainThread?.downgrade_without_webassembly;
  const downgradeBrowserSelection = mainThread?.downgrade_browser_selection;
  const downgradeSimulation = mainThread?.downgrade_simulation;
  const guardedCapabilities = parsed.guarded_capabilities;
  const unsupportedWorkerLadders = mainThreadLifecycle?.unsupported_worker_ladders;
  const serviceWorkerFailClosed = unsupportedWorkerLadders?.service_worker;
  const sharedWorkerFailClosed = unsupportedWorkerLadders?.shared_worker;
  const serviceWorkerBroker = unsupportedWorkerLadders?.service_worker_broker;
  const sharedWorkerCoordinatorMainThread =
    unsupportedWorkerLadders?.shared_worker_coordinator_main_thread;
  const sharedWorkerCoordinatorDedicatedWorker =
    unsupportedWorkerLadders?.shared_worker_coordinator_dedicated_worker;

  assertLifecycle("main-thread lifecycle", mainThreadLifecycle, {
    has_window: true,
    has_document: true,
    has_webassembly: true,
  });
  assertLifecycle("dedicated-worker lifecycle", workerLifecycle, {
    has_window: false,
    has_document: false,
    has_webassembly: true,
  });

  assertLadder("main-thread ladder", mainThreadLadder, {
    supported: true,
    selected_lane: MAIN_THREAD_LANE,
    host_role: "browser_main_thread",
    runtime_context: "browser_main_thread",
    support_class: "direct_runtime_supported",
    reason_code: "supported",
  });
  assertCandidateReason(
    "main-thread ladder",
    mainThreadLadder,
    DEDICATED_WORKER_LANE,
    "candidate_host_role_mismatch",
  );

  assertLadder("preferred dedicated-worker ladder", preferredDedicatedWorker, {
    supported: true,
    selected_lane: MAIN_THREAD_LANE,
    host_role: "browser_main_thread",
    runtime_context: "browser_main_thread",
    support_class: "direct_runtime_supported",
    reason_code: "supported",
  });
  assertCandidateReason(
    "preferred dedicated-worker ladder",
    preferredDedicatedWorker,
    DEDICATED_WORKER_LANE,
    "candidate_host_role_mismatch",
  );
  assert(
    preferredDedicatedWorker?.preferred_lane === DEDICATED_WORKER_LANE,
    `preferred dedicated-worker lane must be requested, got ${preferredDedicatedWorker?.preferred_lane ?? "missing"}`,
  );
  assertBrowserSelection("main-thread browser selection", mainThreadBrowserSelection, {
    supported: true,
    selected_lane: MAIN_THREAD_LANE,
    reason_code: "supported",
    runtime_available: true,
  });
  assertBrowserSelection(
    "preferred dedicated-worker browser selection",
    preferredDedicatedWorkerBrowserSelection,
    {
      supported: true,
      preferred_lane: DEDICATED_WORKER_LANE,
      selected_lane: MAIN_THREAD_LANE,
      reason_code: "supported",
      runtime_available: true,
    },
  );

  assert(downgradeSimulation?.simulated === true, "main-thread downgrade simulation must run");
  assert(
    downgradeSimulation?.skipped_reason === null,
    `main-thread downgrade simulation unexpectedly skipped: ${downgradeSimulation?.skipped_reason ?? "missing"}`,
  );
  assertLadder("downgrade ladder", downgrade, {
    supported: false,
    selected_lane: UNSUPPORTED_LANE,
    host_role: "browser_main_thread",
    runtime_context: "browser_main_thread",
    support_class: "unsupported",
    reason_code: "missing_webassembly",
  });
  assertCandidateReason(
    "downgrade ladder",
    downgrade,
    MAIN_THREAD_LANE,
    "candidate_prerequisite_missing",
  );
  assertBrowserSelection("downgrade browser selection", downgradeBrowserSelection, {
    supported: false,
    selected_lane: UNSUPPORTED_LANE,
    reason_code: "missing_webassembly",
    runtime_available: false,
  });

  assertLadder("service-worker fail-closed ladder", serviceWorkerFailClosed, {
    supported: false,
    selected_lane: UNSUPPORTED_LANE,
    host_role: "service_worker",
    runtime_context: "service_worker",
    support_class: "unsupported",
    reason_code: "service_worker_direct_runtime_not_shipped",
  });
  assert(
    serviceWorkerFailClosed?.runtime_support_reason === "service_worker_not_yet_shipped",
    `service-worker runtime support reason drifted: ${serviceWorkerFailClosed?.runtime_support_reason ?? "missing"}`,
  );
  assert(
    serviceWorkerFailClosed?.capabilities?.storage?.has_indexed_db === true,
    `service-worker fail-closed ladder must still surface IndexedDB availability, got ${serviceWorkerFailClosed?.capabilities?.storage?.has_indexed_db ?? "missing"}`,
  );
  assert(
    serviceWorkerFailClosed?.capabilities?.storage?.has_local_storage === false,
    `service-worker fail-closed ladder must keep localStorage unavailable, got ${serviceWorkerFailClosed?.capabilities?.storage?.has_local_storage ?? "missing"}`,
  );

  assertLadder("shared-worker fail-closed ladder", sharedWorkerFailClosed, {
    supported: false,
    selected_lane: UNSUPPORTED_LANE,
    host_role: "shared_worker",
    runtime_context: "shared_worker",
    support_class: "unsupported",
    reason_code: "shared_worker_direct_runtime_not_shipped",
  });
  assert(
    sharedWorkerFailClosed?.runtime_support_reason === "shared_worker_not_yet_shipped",
    `shared-worker runtime support reason drifted: ${sharedWorkerFailClosed?.runtime_support_reason ?? "missing"}`,
  );
  assert(
    sharedWorkerFailClosed?.capabilities?.storage?.has_indexed_db === true,
    `shared-worker fail-closed ladder must still surface IndexedDB availability, got ${sharedWorkerFailClosed?.capabilities?.storage?.has_indexed_db ?? "missing"}`,
  );
  assert(
    sharedWorkerFailClosed?.capabilities?.storage?.has_local_storage === false,
    `shared-worker fail-closed ladder must keep localStorage unavailable, got ${sharedWorkerFailClosed?.capabilities?.storage?.has_local_storage ?? "missing"}`,
  );

  assertWorkerSupport("service-worker broker support", serviceWorkerBroker, {
    supported: true,
    contract_id: "wasm-service-worker-broker-contract-v1",
    requested_lane: "lane.browser.service_worker.broker",
    fallback_target: DEDICATED_WORKER_LANE,
    fallback_lane_id: DEDICATED_WORKER_LANE,
    host_role: "service_worker",
    runtime_context: "service_worker",
    reason: "supported",
    direct_runtime_reason: "service_worker_not_yet_shipped",
    direct_execution_reason_code: "service_worker_direct_runtime_not_shipped",
  });
  assert(
    serviceWorkerBroker?.capabilities?.storage?.has_indexed_db === true,
    `service-worker broker support must still surface IndexedDB availability, got ${serviceWorkerBroker?.capabilities?.storage?.has_indexed_db ?? "missing"}`,
  );
  assert(
    serviceWorkerBroker?.capabilities?.storage?.has_local_storage === false,
    `service-worker broker support must keep localStorage unavailable, got ${serviceWorkerBroker?.capabilities?.storage?.has_local_storage ?? "missing"}`,
  );

  assertWorkerSupport(
    "shared-worker coordinator main-thread support",
    sharedWorkerCoordinatorMainThread,
    {
      supported: true,
      contract_id: "wasm-shared-worker-tenancy-lifecycle-v1",
      requested_lane: "lane.browser.shared_worker.coordinator",
      fallback_target: MAIN_THREAD_LANE,
      fallback_lane_id: MAIN_THREAD_LANE,
      host_role: "browser_main_thread",
      runtime_context: "browser_main_thread",
      reason: "supported",
      direct_runtime_reason: "shared_worker_not_yet_shipped",
      direct_execution_reason_code: "shared_worker_direct_runtime_not_shipped",
    },
  );
  assertWorkerSupport(
    "shared-worker coordinator dedicated-worker support",
    sharedWorkerCoordinatorDedicatedWorker,
    {
      supported: true,
      contract_id: "wasm-shared-worker-tenancy-lifecycle-v1",
      requested_lane: "lane.browser.shared_worker.coordinator",
      fallback_target: DEDICATED_WORKER_LANE,
      fallback_lane_id: DEDICATED_WORKER_LANE,
      host_role: "dedicated_worker",
      runtime_context: "dedicated_worker",
      reason: "supported",
      direct_runtime_reason: "shared_worker_not_yet_shipped",
      direct_execution_reason_code: "shared_worker_direct_runtime_not_shipped",
    },
  );

  assertLadder("dedicated-worker ladder", workerLadder, {
    supported: true,
    selected_lane: DEDICATED_WORKER_LANE,
    host_role: "dedicated_worker",
    runtime_context: "dedicated_worker",
    support_class: "direct_runtime_supported",
    reason_code: "supported",
  });
  assertCandidateReason(
    "dedicated-worker ladder",
    workerLadder,
    MAIN_THREAD_LANE,
    "candidate_host_role_mismatch",
  );

  assertLadder("preferred main-thread worker ladder", preferredMainThread, {
    supported: true,
    selected_lane: DEDICATED_WORKER_LANE,
    host_role: "dedicated_worker",
    runtime_context: "dedicated_worker",
    support_class: "direct_runtime_supported",
    reason_code: "supported",
  });
  assertCandidateReason(
    "preferred main-thread worker ladder",
    preferredMainThread,
    MAIN_THREAD_LANE,
    "candidate_host_role_mismatch",
  );
  assert(
    preferredMainThread?.preferred_lane === MAIN_THREAD_LANE,
    `preferred main-thread worker lane must be requested, got ${preferredMainThread?.preferred_lane ?? "missing"}`,
  );
  assertBrowserSelection("dedicated-worker browser selection", workerBrowserSelection, {
    supported: true,
    selected_lane: DEDICATED_WORKER_LANE,
    reason_code: "supported",
    runtime_available: true,
  });
  assertBrowserSelection(
    "preferred main-thread worker browser selection",
    preferredMainThreadBrowserSelection,
    {
      supported: true,
      preferred_lane: MAIN_THREAD_LANE,
      selected_lane: DEDICATED_WORKER_LANE,
      reason_code: "supported",
      runtime_available: true,
    },
  );

  assert(
    guardedCapabilities?.main_thread_local_storage === true,
    "main-thread guarded capability snapshot must confirm localStorage availability",
  );
  assert(
    guardedCapabilities?.dedicated_worker_local_storage === false,
    "dedicated worker guarded capability snapshot must keep localStorage unavailable",
  );
  assert(
    typeof guardedCapabilities?.main_thread_indexed_db === "boolean" &&
      typeof guardedCapabilities?.dedicated_worker_indexed_db === "boolean" &&
      typeof guardedCapabilities?.main_thread_web_transport === "boolean" &&
      typeof guardedCapabilities?.dedicated_worker_web_transport === "boolean",
    "guarded capability snapshot must preserve boolean advanced-capability fields",
  );

  result = {
    status: "ok",
    url,
    executable_path: executablePath,
    scenario_id: parsed.scenario_id,
    support_lane: parsed.support_lane,
    diagnostics_clean: mainThreadLifecycle.diagnostics_clean,
    ready_phase: mainThreadLifecycle.ready_phase,
    disposed_phase: mainThreadLifecycle.disposed_phase,
    child_scope_count_before_unmount: mainThreadLifecycle.child_scope_count_before_unmount,
    active_task_count_before_unmount: mainThreadLifecycle.active_task_count_before_unmount,
    completed_task_outcome: mainThreadLifecycle.completed_task_outcome,
    cancel_event_count: mainThreadLifecycle.cancel_event_count,
    dispatch_count: mainThreadLifecycle.dispatch_count,
    event_symbols: mainThreadLifecycle.event_symbols,
    capabilities: mainThreadLifecycle.capabilities,
    main_thread_selected_lane: mainThreadLadder.selected_lane,
    main_thread_browser_selection_lane: mainThreadBrowserSelection.selected_lane,
    main_thread_preferred_worker_selected_lane: preferredDedicatedWorker.selected_lane,
    main_thread_preferred_worker_browser_selection_lane:
      preferredDedicatedWorkerBrowserSelection.selected_lane,
    main_thread_preferred_worker_reason_code: preferredDedicatedWorker.reason_code,
    service_worker_fail_closed_reason_code: serviceWorkerFailClosed.reason_code,
    shared_worker_fail_closed_reason_code: sharedWorkerFailClosed.reason_code,
    service_worker_broker_reason: serviceWorkerBroker.reason,
    shared_worker_coordinator_main_thread_reason: sharedWorkerCoordinatorMainThread.reason,
    shared_worker_coordinator_dedicated_worker_reason:
      sharedWorkerCoordinatorDedicatedWorker.reason,
    downgrade_selected_lane: downgrade.selected_lane,
    downgrade_browser_selection_lane: downgradeBrowserSelection.selected_lane,
    downgrade_reason_code: downgrade.reason_code,
    dedicated_worker_ready_phase: workerLifecycle.ready_phase,
    dedicated_worker_disposed_phase: workerLifecycle.disposed_phase,
    dedicated_worker_completed_task_outcome: workerLifecycle.completed_task_outcome,
    dedicated_worker_cancel_event_count: workerLifecycle.cancel_event_count,
    dedicated_worker_selected_lane: workerLadder.selected_lane,
    dedicated_worker_browser_selection_lane: workerBrowserSelection.selected_lane,
    dedicated_worker_preferred_main_thread_selected_lane: preferredMainThread.selected_lane,
    dedicated_worker_preferred_main_thread_browser_selection_lane:
      preferredMainThreadBrowserSelection.selected_lane,
    dedicated_worker_preferred_main_thread_reason_code: preferredMainThread.reason_code,
    main_thread_local_storage: guardedCapabilities.main_thread_local_storage,
    dedicated_worker_local_storage: guardedCapabilities.dedicated_worker_local_storage,
    main_thread_indexed_db: guardedCapabilities.main_thread_indexed_db,
    dedicated_worker_indexed_db: guardedCapabilities.dedicated_worker_indexed_db,
    main_thread_web_transport: guardedCapabilities.main_thread_web_transport,
    dedicated_worker_web_transport: guardedCapabilities.dedicated_worker_web_transport,
  };
} catch (error) {
  caughtError = error;
  result = {
    status: "error",
    url,
    executable_path: executablePath,
    message: error instanceof Error ? error.message : String(error),
  };
} finally {
  writeResult(result);
  if (browser) {
    await browser.close();
  }
  if (serverHandle) {
    await new Promise((resolve, reject) => {
      serverHandle.server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve();
      });
    });
  }
}

if (caughtError) {
  throw caughtError;
}

console.log(JSON.stringify(result, null, 2));
