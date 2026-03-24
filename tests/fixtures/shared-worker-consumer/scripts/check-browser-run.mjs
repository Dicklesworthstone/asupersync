import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { chromium } from "playwright-core";

const distDir = path.resolve("dist");
const outputPath = process.argv[2] ? path.resolve(process.argv[2]) : null;
const SHARED_WORKER_LANE = "lane.browser.shared_worker.coordinator";
const MAIN_THREAD_LANE = "lane.browser.main_thread.direct_runtime";

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
    case ".ts":
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
  const normalized = decodeURIComponent(
    urlPathname === "/" ? "/index.html" : urlPathname,
  );
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
      response.writeHead(200, {
        "cache-control": "no-store",
        "content-type": contentTypeFor(filePath),
      });
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

async function waitForFixtureState(page) {
  await page.waitForFunction(() => {
    const node = document.querySelector("#status");
    if (!node) {
      return false;
    }
    const text = node.textContent ?? "";
    if (!text) {
      return false;
    }
    try {
      const parsed = JSON.parse(text);
      return (
        parsed.phase === "closed"
        || parsed.phase === "fallback_complete"
        || parsed.phase === "error"
      );
    } catch {
      return false;
    }
  });

  const statusText = await page.locator("#status").textContent();
  if (!statusText) {
    throw new Error("fixture completed without status text");
  }
  let parsed;
  try {
    parsed = JSON.parse(statusText);
  } catch (error) {
    throw new Error(
      `fixture rendered invalid JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (parsed.phase === "error") {
    throw new Error(
      `[${parsed.client_id ?? "unknown"}] ${parsed.error_message ?? "unknown error"}`,
    );
  }
  return parsed;
}

async function runScenario(page, baseUrl, params) {
  const query = new URLSearchParams(params);
  await page.goto(`${baseUrl}/index.html?${query.toString()}`, {
    waitUntil: "domcontentloaded",
  });
  return waitForFixtureState(page);
}

if (!fs.existsSync(distDir)) {
  throw new Error(`Missing dist directory: ${distDir}`);
}

const executablePath = detectChromiumExecutable();
let browser;
let serverHandle;
let result;
let caughtError = null;

try {
  serverHandle = await startStaticServer();
  browser = await chromium.launch({
    executablePath,
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });

  const context = await browser.newContext();
  const baseUrl = `http://127.0.0.1:${serverHandle.port}`;

  const reusePageOne = await context.newPage();
  const reusePageTwo = await context.newPage();

  const [reuseOneState, reuseTwoState] = await Promise.all([
    runScenario(reusePageOne, baseUrl, {
      clientId: "page-one",
      scenario: "shared-worker-reuse-page-one",
      expectedClients: "2",
      workerName: "shared-worker-reuse-cluster",
    }),
    runScenario(reusePageTwo, baseUrl, {
      clientId: "page-two",
      scenario: "shared-worker-reuse-page-two",
      expectedClients: "2",
      workerName: "shared-worker-reuse-cluster",
    }),
  ]);

  const mismatchPage = await context.newPage();
  const mismatchState = await runScenario(mismatchPage, baseUrl, {
    clientId: "protocol-mismatch",
    scenario: "shared-worker-protocol-mismatch",
    expectedClients: "1",
    workerName: "shared-worker-mismatch-cluster",
    coordinatorProtocolVersion: "2",
  });

  const crashPage = await context.newPage();
  const crashState = await runScenario(crashPage, baseUrl, {
    clientId: "crash-before-handshake",
    scenario: "shared-worker-crash-fallback",
    expectedClients: "1",
    workerName: "shared-worker-crash-cluster",
    forceCrashBeforeHandshake: "1",
    handshakeTimeoutMs: "250",
  });

  assert(
    reuseOneState.selection?.selectedMode === "shared_worker",
    `expected reuse page one to stay on shared_worker, got ${reuseOneState.selection?.selectedMode ?? "missing"}`,
  );
  assert(
    reuseTwoState.selection?.selectedMode === "shared_worker",
    `expected reuse page two to stay on shared_worker, got ${reuseTwoState.selection?.selectedMode ?? "missing"}`,
  );
  assert(
    reuseOneState.attach?.requestedLane === SHARED_WORKER_LANE,
    `unexpected requested lane for reuse page one: ${reuseOneState.attach?.requestedLane ?? "missing"}`,
  );
  assert(
    reuseTwoState.attach?.requestedLane === SHARED_WORKER_LANE,
    `unexpected requested lane for reuse page two: ${reuseTwoState.attach?.requestedLane ?? "missing"}`,
  );

  const reuseOneSnapshot = reuseOneState.topology_snapshot;
  const reuseTwoSnapshot = reuseTwoState.topology_snapshot;
  assert(
    reuseOneSnapshot?.clientCount === 2,
    `expected reuse page one to observe 2 clients, got ${reuseOneSnapshot?.clientCount ?? "missing"}`,
  );
  assert(
    reuseTwoSnapshot?.clientCount === 2,
    `expected reuse page two to observe 2 clients, got ${reuseTwoSnapshot?.clientCount ?? "missing"}`,
  );
  assert(
    Array.isArray(reuseOneSnapshot?.clientIds)
      && reuseOneSnapshot.clientIds.includes("page-one")
      && reuseOneSnapshot.clientIds.includes("page-two"),
    "reuse page one snapshot must include both page-one and page-two",
  );
  assert(
    Array.isArray(reuseTwoSnapshot?.clientIds)
      && reuseTwoSnapshot.clientIds.includes("page-one")
      && reuseTwoSnapshot.clientIds.includes("page-two"),
    "reuse page two snapshot must include both page-one and page-two",
  );
  assert(
    reuseOneSnapshot?.workerName === "shared-worker-reuse-cluster"
      && reuseTwoSnapshot?.workerName === "shared-worker-reuse-cluster",
    "reuse pages must observe the same coordinator worker name",
  );
  assert(
    reuseOneState.close_lifecycle_state === "terminated",
    `expected reuse page one to close into terminated state, got ${reuseOneState.close_lifecycle_state ?? "missing"}`,
  );
  assert(
    reuseTwoState.close_lifecycle_state === "terminated",
    `expected reuse page two to close into terminated state, got ${reuseTwoState.close_lifecycle_state ?? "missing"}`,
  );

  assert(
    mismatchState.selection?.selectedMode === "fallback",
    `expected mismatch scenario to fall back, got ${mismatchState.selection?.selectedMode ?? "missing"}`,
  );
  assert(
    mismatchState.selection?.reason === "coordinator_protocol_version_mismatch",
    `unexpected mismatch reason: ${mismatchState.selection?.reason ?? "missing"}`,
  );
  assert(
    mismatchState.selection?.fallbackLaneId === MAIN_THREAD_LANE,
    `unexpected mismatch fallback lane id: ${mismatchState.selection?.fallbackLaneId ?? "missing"}`,
  );
  assert(
    mismatchState.fallback_runtime?.executionLadder?.selectedLane === MAIN_THREAD_LANE,
    `unexpected mismatch runtime lane: ${mismatchState.fallback_runtime?.executionLadder?.selectedLane ?? "missing"}`,
  );

  assert(
    crashState.selection?.selectedMode === "fallback",
    `expected crash scenario to fall back, got ${crashState.selection?.selectedMode ?? "missing"}`,
  );
  assert(
    crashState.selection?.reason === "coordinator_bootstrap_failure",
    `unexpected crash fallback reason: ${crashState.selection?.reason ?? "missing"}`,
  );
  assert(
    crashState.selection?.fallbackLaneId === MAIN_THREAD_LANE,
    `unexpected crash fallback lane id: ${crashState.selection?.fallbackLaneId ?? "missing"}`,
  );
  assert(
    crashState.fallback_runtime?.executionLadder?.selectedLane === MAIN_THREAD_LANE,
    `unexpected crash runtime lane: ${crashState.fallback_runtime?.executionLadder?.selectedLane ?? "missing"}`,
  );

  const scenarioInventory = [
    {
      scenario_id: "shared_worker_attach_baseline",
      failure_family: "baseline",
      expected_outcome: "browser page attaches to the SharedWorker coordinator on the supported path",
      artifact_keys: ["browser_run"],
    },
    {
      scenario_id: "shared_worker_multi_page_reuse",
      failure_family: "reuse",
      expected_outcome: "two same-origin pages observe one coordinator topology with both clients present",
      artifact_keys: ["browser_run"],
    },
    {
      scenario_id: "shared_worker_protocol_mismatch_fallback",
      failure_family: "version_mismatch",
      expected_outcome: "protocol drift falls back cleanly instead of attaching partially",
      artifact_keys: ["browser_run"],
    },
    {
      scenario_id: "shared_worker_attach_crash_fallback",
      failure_family: "worker_loss",
      expected_outcome: "pre-handshake coordinator loss downgrades explicitly to the fallback lane",
      artifact_keys: ["browser_run"],
    },
    {
      scenario_id: "shared_worker_client_detach_cleanup",
      failure_family: "cleanup",
      expected_outcome: "browser-side clients close explicitly and report terminated lifecycle state",
      artifact_keys: ["browser_run"],
    },
  ];

  result = {
    status: "ok",
    scenario_id: "SHARED-WORKER-CONSUMER",
    reuse_page_one_mode: reuseOneState.selection.selectedMode,
    reuse_page_two_mode: reuseTwoState.selection.selectedMode,
    reuse_page_one_client_count: reuseOneSnapshot.clientCount,
    reuse_page_two_client_count: reuseTwoSnapshot.clientCount,
    reuse_page_one_attach_count: reuseOneSnapshot.attachCount,
    reuse_page_two_attach_count: reuseTwoSnapshot.attachCount,
    reuse_worker_name: reuseOneSnapshot.workerName,
    reuse_client_ids: reuseOneSnapshot.clientIds,
    mismatch_mode: mismatchState.selection.selectedMode,
    mismatch_reason: mismatchState.selection.reason,
    mismatch_fallback_lane_id: mismatchState.selection.fallbackLaneId,
    crash_mode: crashState.selection.selectedMode,
    crash_reason: crashState.selection.reason,
    crash_fallback_lane_id: crashState.selection.fallbackLaneId,
    close_lifecycle_states: [
      reuseOneState.close_lifecycle_state,
      reuseTwoState.close_lifecycle_state,
    ],
    scenario_inventory: scenarioInventory,
  };
} catch (error) {
  caughtError = error;
  result = {
    status: "error",
    message: error instanceof Error ? error.message : String(error),
  };
} finally {
  writeResult(result);
  if (browser) {
    await browser.close();
  }
  if (serverHandle?.server) {
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
