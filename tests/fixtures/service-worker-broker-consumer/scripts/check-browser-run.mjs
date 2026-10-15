import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { chromium } from "playwright-core";

const distDir = path.resolve("dist");
const outputPath = process.argv[2] ? path.resolve(process.argv[2]) : null;
const SERVICE_WORKER_BROKER_LANE = "lane.browser.service_worker.broker";
const DEDICATED_WORKER_LANE = "lane.browser.dedicated_worker.direct_runtime";

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
  const page = await browser.newPage();
  const url = `http://127.0.0.1:${serverHandle.port}/index.html`;

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
      return parsed.phase === "cleanup_complete" || parsed.phase === "error";
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
    throw new Error(`fixture rendered error payload: ${parsed.error_message ?? "unknown error"}`);
  }
  if (parsed.scenario_id !== "SERVICE-WORKER-BROKER-CONSUMER") {
    throw new Error(`unexpected scenario_id: ${parsed.scenario_id ?? "missing"}`);
  }

  const broker = parsed.broker_result;
  if (!broker) {
    throw new Error("service-worker broker payload missing from browser-run state");
  }

  const firstWork = Array.isArray(broker.pendingWork) ? broker.pendingWork[0] : null;
  const firstHandoff = Array.isArray(broker.handoffs) ? broker.handoffs[0] : null;

  assert(parsed.phase === "cleanup_complete", `expected cleanup_complete, got ${parsed.phase}`);
  assert(parsed.controller_ready === true, "service-worker controller was not established");
  assert(parsed.unregistered === true, "service worker must unregister after reporting");
  assert(Array.isArray(parsed.events), "expected rendered service-worker events");
  assert(
    parsed.events.some((event) => event.type === "service-worker-broker-ready"),
    "service-worker-broker-ready event missing from rendered state",
  );

  assert(broker.support?.supported === true, "broker support must be admitted");
  assert(
    broker.support?.hostRole === "service_worker",
    `unexpected broker host role: ${broker.support?.hostRole ?? "missing"}`,
  );
  assert(
    broker.support?.runtimeContext === "service_worker",
    `unexpected broker runtime context: ${broker.support?.runtimeContext ?? "missing"}`,
  );
  assert(
    broker.support?.reason === "supported",
    `unexpected broker support reason: ${broker.support?.reason ?? "missing"}`,
  );
  assert(
    broker.support?.directExecutionReasonCode === "service_worker_direct_runtime_not_shipped",
    `unexpected direct execution reason: ${broker.support?.directExecutionReasonCode ?? "missing"}`,
  );

  assert(
    broker.registration?.requestedLane === SERVICE_WORKER_BROKER_LANE,
    `unexpected broker requested lane: ${broker.registration?.requestedLane ?? "missing"}`,
  );
  assert(
    broker.registration?.fallbackLaneId === DEDICATED_WORKER_LANE,
    `unexpected broker fallback lane id: ${broker.registration?.fallbackLaneId ?? "missing"}`,
  );
  assert(
    broker.registration?.lifecycleState === "quiescent",
    `unexpected broker lifecycle state: ${broker.registration?.lifecycleState ?? "missing"}`,
  );

  assert(Array.isArray(broker.pendingWork), "pendingWork must be an array");
  assert(
    broker.pendingWork.length === 1,
    `expected one pending work record, got ${broker.pendingWork.length}`,
  );
  assert(
    firstWork?.requestedLane === SERVICE_WORKER_BROKER_LANE,
    "pending work requested lane drifted",
  );

  assert(Array.isArray(broker.handoffs), "handoffs must be an array");
  assert(
    broker.handoffs.length === 1,
    `expected one handoff record, got ${broker.handoffs.length}`,
  );
  assert(
    firstHandoff?.targetLaneId === DEDICATED_WORKER_LANE,
    `unexpected handoff target lane: ${firstHandoff?.targetLaneId ?? "missing"}`,
  );
  assert(
    firstHandoff?.reason === "service_worker_direct_runtime_not_shipped",
    `unexpected handoff reason: ${firstHandoff?.reason ?? "missing"}`,
  );

  assert(
    broker.reopened?.registration?.lifecycleState === "quiescent",
    `unexpected reopened lifecycle state: ${broker.reopened?.registration?.lifecycleState ?? "missing"}`,
  );
  assert(
    broker.reopened?.pendingWorkCount === 1,
    `unexpected reopened pending work count: ${broker.reopened?.pendingWorkCount ?? "missing"}`,
  );
  assert(
    broker.reopened?.handoffCount === 1,
    `unexpected reopened handoff count: ${broker.reopened?.handoffCount ?? "missing"}`,
  );

  assert(broker.mismatch?.supported === false, "mismatch diagnostics must fail closed");
  assert(
    broker.mismatch?.reason === "broker_protocol_version_mismatch",
    `unexpected mismatch reason: ${broker.mismatch?.reason ?? "missing"}`,
  );

  assert(
    Number.isInteger(broker.clearedCount) && broker.clearedCount >= 3,
    `expected cleanup to clear at least 3 records, got ${broker.clearedCount ?? "missing"}`,
  );
  assert(
    broker.postCleanup?.registrationMissing === true,
    "post-cleanup registration must be missing",
  );
  assert(
    broker.postCleanup?.pendingWorkCount === 0,
    `unexpected post-cleanup pending work count: ${broker.postCleanup?.pendingWorkCount ?? "missing"}`,
  );
  assert(
    broker.postCleanup?.handoffCount === 0,
    `unexpected post-cleanup handoff count: ${broker.postCleanup?.handoffCount ?? "missing"}`,
  );

  result = {
    status: "ok",
    scenario_id: parsed.scenario_id,
    final_phase: parsed.phase,
    controller_ready: parsed.controller_ready,
    broker_supported: broker.support.supported,
    broker_reason: broker.support.reason,
    broker_runtime_context: broker.support.runtimeContext,
    direct_execution_reason_code: broker.support.directExecutionReasonCode,
    registration_requested_lane: broker.registration.requestedLane,
    registration_fallback_lane_id: broker.registration.fallbackLaneId,
    registration_lifecycle_state: broker.registration.lifecycleState,
    pending_work_count: broker.pendingWork.length,
    reopened_pending_work_count: broker.reopened.pendingWorkCount,
    handoff_count: broker.handoffs.length,
    reopened_handoff_count: broker.reopened.handoffCount,
    handoff_target_lane_id: firstHandoff.targetLaneId,
    handoff_reason: firstHandoff.reason,
    mismatch_supported: broker.mismatch.supported,
    mismatch_reason: broker.mismatch.reason,
    cleared_count: broker.clearedCount,
    post_cleanup_registration_missing: broker.postCleanup.registrationMissing,
    post_cleanup_pending_work_count: broker.postCleanup.pendingWorkCount,
    post_cleanup_handoff_count: broker.postCleanup.handoffCount,
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
