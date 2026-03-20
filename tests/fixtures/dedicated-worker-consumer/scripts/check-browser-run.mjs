import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { chromium } from "playwright-core";

const distDir = path.resolve("dist");
const outputPath = process.argv[2] ? path.resolve(process.argv[2]) : null;
const DEDICATED_WORKER_LANE = "lane.browser.dedicated_worker.direct_runtime";
const MAIN_THREAD_LANE = "lane.browser.main_thread.direct_runtime";
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
    if (!text) {
      return false;
    }
    try {
      const parsed = JSON.parse(text);
      return parsed.phase === "shutdown_complete" || parsed.phase === "worker_error";
    } catch {
      return false;
    }
  });

  const statusText = await page.locator("#status").textContent();
  if (!statusText) {
    throw new Error("browser run completed without status text");
  }

  const parsed = JSON.parse(statusText);
  if (parsed.phase === "worker_error") {
    throw new Error(`fixture rendered worker_error payload: ${parsed.error_message ?? "unknown error"}`);
  }
  if (parsed.scenario_id !== "DEDICATED-WORKER-CONSUMER") {
    throw new Error(`unexpected scenario_id: ${parsed.scenario_id ?? "missing"}`);
  }

  const bootstrap = parsed.worker_bootstrap;
  if (!bootstrap) {
    throw new Error("worker bootstrap payload missing from browser-run state");
  }

  const preferredCandidate = bootstrap.runtimeSelectionDemoted.candidateReasons.find(
    (candidate) => candidate.laneId === DEDICATED_WORKER_LANE,
  );

  assert(parsed.phase === "shutdown_complete", `expected final phase shutdown_complete, got ${parsed.phase}`);
  assert(parsed.shutdown_reason === "fixture-handoff-complete", `unexpected shutdown_reason: ${parsed.shutdown_reason ?? "missing"}`);
  assert(Array.isArray(parsed.events), "expected rendered worker events");
  assert(parsed.events.some((event) => event.type === "worker-bootstrap"), "worker-bootstrap event missing from rendered state");
  assert(parsed.events.some((event) => event.type === "worker-shutdown-complete"), "worker-shutdown-complete event missing from rendered state");
  assert(bootstrap.support.runtimeContext === "dedicated_worker", `unexpected runtime context: ${bootstrap.support.runtimeContext ?? "missing"}`);
  assert(bootstrap.runtimeSelectionBaseline.supported === true, "baseline runtime selection must stay supported");
  assert(
    bootstrap.runtimeSelectionBaseline.selectedLane === DEDICATED_WORKER_LANE,
    `baseline selection chose unexpected lane: ${bootstrap.runtimeSelectionBaseline.selectedLane ?? "missing"}`,
  );
  assert(
    bootstrap.scopeSelectionBaseline.outcome === "ok",
    `baseline scope selection must succeed, got ${bootstrap.scopeSelectionBaseline.outcome ?? "missing"}`,
  );
  assert(
    bootstrap.scopeSelectionBaseline.selectedLane === DEDICATED_WORKER_LANE,
    `baseline scope selection chose unexpected lane: ${bootstrap.scopeSelectionBaseline.selectedLane ?? "missing"}`,
  );
  assert(
    bootstrap.scopeSelectionPreferredMainThread.outcome === "ok",
    `preferred main-thread scope selection must not throw, got ${bootstrap.scopeSelectionPreferredMainThread.outcome ?? "missing"}`,
  );
  assert(
    bootstrap.scopeSelectionPreferredMainThread.selectedLane === DEDICATED_WORKER_LANE,
    `preferred main-thread scope selection must stay on the truthful worker lane, got ${bootstrap.scopeSelectionPreferredMainThread.selectedLane ?? "missing"}`,
  );
  assert(
    bootstrap.scopeSelectionPreferredMainThread.preferredLane === MAIN_THREAD_LANE,
    `preferred main-thread scope selection must report the requested lane, got ${bootstrap.scopeSelectionPreferredMainThread.preferredLane ?? "missing"}`,
  );
  assert(
    bootstrap.laneHealthDemotion.status === "demoted",
    `lane health demotion must report demoted, got ${bootstrap.laneHealthDemotion.status ?? "missing"}`,
  );
  assert(
    bootstrap.runtimeSelectionDemoted.supported === false,
    "demoted runtime selection must fail closed to unsupported",
  );
  assert(
    bootstrap.runtimeSelectionDemoted.selectedLane === UNSUPPORTED_LANE,
    `demoted runtime selection chose unexpected lane: ${bootstrap.runtimeSelectionDemoted.selectedLane ?? "missing"}`,
  );
  assert(
    bootstrap.runtimeSelectionDemoted.reasonCode === "demote_due_to_lane_health",
    `demoted runtime selection reason mismatch: ${bootstrap.runtimeSelectionDemoted.reasonCode ?? "missing"}`,
  );
  assert(
    bootstrap.runtimeSelectionDemoted.outcome === null,
    `demoted runtime selection must stay on the no-throw path, got ${bootstrap.runtimeSelectionDemoted.outcome ?? "missing"}`,
  );
  assert(preferredCandidate?.reasonCode === "candidate_lane_unhealthy", "demoted candidate matrix must preserve candidate_lane_unhealthy for the worker lane");
  assert(
    bootstrap.laneHealthReset.status === "healthy",
    `lane health reset must report healthy, got ${bootstrap.laneHealthReset.status ?? "missing"}`,
  );
  assert(
    bootstrap.runtimeSelectionRecovered.supported === true,
    "recovered runtime selection must restore support",
  );
  assert(
    bootstrap.runtimeSelectionRecovered.selectedLane === DEDICATED_WORKER_LANE,
    `recovered runtime selection chose unexpected lane: ${bootstrap.runtimeSelectionRecovered.selectedLane ?? "missing"}`,
  );
  assert(
    bootstrap.runtimeSelectionRecovered.outcome === "ok",
    `recovered runtime selection must return ok, got ${bootstrap.runtimeSelectionRecovered.outcome ?? "missing"}`,
  );
  assert(
    bootstrap.storageExercise?.backend === "indexeddb",
    `worker storage exercise must use indexeddb, got ${bootstrap.storageExercise?.backend ?? "missing"}`,
  );
  assert(
    bootstrap.artifactExercise?.downloadFailureCode === "ASUPERSYNC_BROWSER_ARTIFACT_DOWNLOAD_UNSUPPORTED",
    `unexpected worker artifact download failure code: ${bootstrap.artifactExercise?.downloadFailureCode ?? "missing"}`,
  );
  assert(
    bootstrap.artifactExercise?.quotaFailureReason === "quota_exceeded",
    `unexpected worker artifact quota failure reason: ${bootstrap.artifactExercise?.quotaFailureReason ?? "missing"}`,
  );

  result = {
    status: "ok",
    url,
    executable_path: executablePath,
    scenario_id: parsed.scenario_id,
    final_phase: parsed.phase,
    shutdown_reason: parsed.shutdown_reason,
    support_runtime_context: bootstrap.support.runtimeContext,
    baseline_selected_lane: bootstrap.runtimeSelectionBaseline.selectedLane,
    baseline_scope_outcome: bootstrap.scopeSelectionBaseline.outcome,
    preferred_scope_selected_lane: bootstrap.scopeSelectionPreferredMainThread.selectedLane,
    preferred_scope_outcome: bootstrap.scopeSelectionPreferredMainThread.outcome,
    demotion_status: bootstrap.laneHealthDemotion.status,
    demoted_selected_lane: bootstrap.runtimeSelectionDemoted.selectedLane,
    demoted_reason_code: bootstrap.runtimeSelectionDemoted.reasonCode,
    demoted_outcome: bootstrap.runtimeSelectionDemoted.outcome,
    demoted_worker_candidate_reason: preferredCandidate?.reasonCode ?? null,
    recovered_status: bootstrap.laneHealthReset.status,
    recovered_selected_lane: bootstrap.runtimeSelectionRecovered.selectedLane,
    recovered_outcome: bootstrap.runtimeSelectionRecovered.outcome,
    storage_backend: bootstrap.storageExercise?.backend ?? null,
    artifact_download_failure_code: bootstrap.artifactExercise?.downloadFailureCode ?? null,
    quota_failure_reason: bootstrap.artifactExercise?.quotaFailureReason ?? null,
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
