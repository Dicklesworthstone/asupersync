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

function buildScenarioInventory(bootstrap, preferredCandidate, prerequisiteLossCandidate, parsed) {
  return [
    {
      scenario_id: "worker_bootstrap_baseline",
      failure_family: "baseline",
      expected_outcome: "dedicated worker direct runtime stays selected on the no-throw path",
      artifact_keys: ["browser_run"],
      observed: {
        selected_lane: bootstrap.runtimeSelectionBaseline.selectedLane,
        scope_outcome: bootstrap.scopeSelectionBaseline.outcome,
      },
    },
    {
      scenario_id: "preferred_lane_mismatch_truthful_worker_selection",
      failure_family: "preferred_lane_mismatch",
      expected_outcome: "requested main-thread preference stays truthful to the worker lane",
      artifact_keys: ["browser_run"],
      observed: {
        preferred_lane: bootstrap.scopeSelectionPreferredMainThread.preferredLane,
        selected_lane: bootstrap.scopeSelectionPreferredMainThread.selectedLane,
        outcome: bootstrap.scopeSelectionPreferredMainThread.outcome,
      },
    },
    {
      scenario_id: "worker_loss_retry_window",
      failure_family: "worker_loss",
      expected_outcome: "first worker loss consumes retry budget without silent downgrade",
      artifact_keys: ["browser_run"],
      observed: {
        lane_health_status: bootstrap.laneHealthRetrying.status,
        trigger: bootstrap.laneHealthRetrying.lastTrigger,
        retry_budget_remaining: bootstrap.laneHealthRetrying.retryBudgetRemaining,
        selected_lane: bootstrap.executionLadderRetrying.selectedLane,
      },
    },
    {
      scenario_id: "worker_loss_fail_closed_demotion",
      failure_family: "worker_loss",
      expected_outcome: "exhausted retry budget demotes fail-closed instead of silently falling through",
      artifact_keys: ["browser_run"],
      observed: {
        lane_health_status: bootstrap.laneHealthDemotion.status,
        demoted_to_lane_id: bootstrap.laneHealthDemotion.demotedToLaneId,
        failure_count: bootstrap.laneHealthDemotion.failureCount,
        reason_code: bootstrap.runtimeSelectionDemoted.reasonCode,
        candidate_reason: preferredCandidate?.reasonCode ?? null,
      },
    },
    {
      scenario_id: "prerequisite_drift_reason_precedence",
      failure_family: "prerequisite_drift",
      expected_outcome: "current prerequisite loss outranks stale demotion state",
      artifact_keys: ["browser_run"],
      observed: {
        reason_code: bootstrap.runtimeSelectionPrerequisiteLoss?.reasonCode ?? null,
        health_status: bootstrap.runtimeSelectionPrerequisiteLoss?.health?.status ?? null,
        stale_health_trigger:
          bootstrap.runtimeSelectionPrerequisiteLoss?.health?.lastTrigger ?? null,
        candidate_reason: prerequisiteLossCandidate?.reasonCode ?? null,
      },
    },
    {
      scenario_id: "lane_health_recovery",
      failure_family: "recovery",
      expected_outcome: "health reset restores the dedicated worker lane",
      artifact_keys: ["browser_run"],
      observed: {
        lane_health_status: bootstrap.laneHealthReset.status,
        selected_lane: bootstrap.runtimeSelectionRecovered.selectedLane,
        outcome: bootstrap.runtimeSelectionRecovered.outcome,
      },
    },
    {
      scenario_id: "graceful_shutdown_handoff",
      failure_family: "shutdown",
      expected_outcome: "fixture reaches shutdown_complete after worker handoff",
      artifact_keys: ["browser_run"],
      observed: {
        final_phase: parsed.phase,
        shutdown_reason: parsed.shutdown_reason,
      },
    },
  ];
}

function buildArtifacts(url) {
  return {
    browser_run: outputPath,
    dist_dir: distDir,
    entry_html: path.join(distDir, "index.html"),
    served_url: url,
  };
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
  const prerequisiteLossCandidate =
    bootstrap.runtimeSelectionPrerequisiteLoss?.candidateReasons.find(
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
    bootstrap.laneHealthRetrying.status === "retrying",
    `lane health retrying step must report retrying, got ${bootstrap.laneHealthRetrying.status ?? "missing"}`,
  );
  assert(
    bootstrap.laneHealthRetrying.failureCount === 1,
    `lane health retrying step must record one failure, got ${bootstrap.laneHealthRetrying.failureCount ?? "missing"}`,
  );
  assert(
    bootstrap.laneHealthRetrying.retryBudgetRemaining === 1,
    `lane health retrying step must preserve one retry budget, got ${bootstrap.laneHealthRetrying.retryBudgetRemaining ?? "missing"}`,
  );
  assert(
    bootstrap.laneHealthRetrying.cooldownUntilMs === null,
    `lane health retrying step must not start cooldown yet, got ${bootstrap.laneHealthRetrying.cooldownUntilMs ?? "missing"}`,
  );
  assert(
    bootstrap.laneHealthRetrying.lastTrigger === "worker_crash",
    `lane health retrying step must record worker_crash, got ${bootstrap.laneHealthRetrying.lastTrigger ?? "missing"}`,
  );
  assert(
    bootstrap.executionLadderRetrying.supported === true,
    "retrying execution ladder must stay on the supported worker lane",
  );
  assert(
    bootstrap.executionLadderRetrying.selectedLane === DEDICATED_WORKER_LANE,
    `retrying execution ladder chose unexpected lane: ${bootstrap.executionLadderRetrying.selectedLane ?? "missing"}`,
  );
  assert(
    bootstrap.executionLadderRetrying.health.status === "retrying",
    `retrying execution ladder must expose retrying health, got ${bootstrap.executionLadderRetrying.health?.status ?? "missing"}`,
  );
  assert(
    bootstrap.executionLadderRetrying.reasonCode === "supported",
    `retrying execution ladder must remain on the supported reason code, got ${bootstrap.executionLadderRetrying.reasonCode ?? "missing"}`,
  );
  assert(
    bootstrap.executionLadderRetrying.health.retryBudgetRemaining === 1,
    `retrying execution ladder must preserve retry budget, got ${bootstrap.executionLadderRetrying.health?.retryBudgetRemaining ?? "missing"}`,
  );
  assert(
    bootstrap.laneHealthDemotion.status === "demoted",
    `lane health demotion must report demoted, got ${bootstrap.laneHealthDemotion.status ?? "missing"}`,
  );
  assert(
    bootstrap.laneHealthDemotion.failureCount === 2,
    `lane health demotion must record two failures, got ${bootstrap.laneHealthDemotion.failureCount ?? "missing"}`,
  );
  assert(
    bootstrap.laneHealthDemotion.retryBudgetRemaining === 0,
    `lane health demotion must exhaust retry budget, got ${bootstrap.laneHealthDemotion.retryBudgetRemaining ?? "missing"}`,
  );
  assert(
    bootstrap.laneHealthDemotion.cooldownUntilMs !== null,
    "lane health demotion must start a cooldown window",
  );
  assert(
    bootstrap.laneHealthDemotion.lastTrigger === "worker_bootstrap_timeout",
    `lane health demotion must record worker_bootstrap_timeout, got ${bootstrap.laneHealthDemotion.lastTrigger ?? "missing"}`,
  );
  assert(
    bootstrap.laneHealthDemotion.demotedToLaneId === UNSUPPORTED_LANE,
    `lane health demotion must fail closed to ${UNSUPPORTED_LANE}, got ${bootstrap.laneHealthDemotion.demotedToLaneId ?? "missing"}`,
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
  assert(
    bootstrap.runtimeSelectionDemoted.health.status === "demoted",
    `demoted runtime selection must surface demoted health, got ${bootstrap.runtimeSelectionDemoted.health?.status ?? "missing"}`,
  );
  assert(
    bootstrap.runtimeSelectionDemoted.health.lastTrigger === "worker_bootstrap_timeout",
    `demoted runtime selection must preserve worker_bootstrap_timeout, got ${bootstrap.runtimeSelectionDemoted.health?.lastTrigger ?? "missing"}`,
  );
  assert(
    bootstrap.runtimeSelectionDemoted.health.demotedToLaneId === UNSUPPORTED_LANE,
    `demoted runtime selection must preserve fail-closed demoted lane ${UNSUPPORTED_LANE}, got ${bootstrap.runtimeSelectionDemoted.health?.demotedToLaneId ?? "missing"}`,
  );
  assert(preferredCandidate?.reasonCode === "candidate_lane_unhealthy", "demoted candidate matrix must preserve candidate_lane_unhealthy for the worker lane");
  assert(
    bootstrap.prerequisiteLossSimulation?.simulated === true,
    `prerequisite-loss simulation must run, got ${bootstrap.prerequisiteLossSimulation?.simulated ?? "missing"}`,
  );
  assert(
    bootstrap.prerequisiteLossSimulation?.skippedReason === null,
    `prerequisite-loss simulation unexpectedly skipped: ${bootstrap.prerequisiteLossSimulation?.skippedReason ?? "missing"}`,
  );
  assert(
    bootstrap.runtimeSelectionPrerequisiteLoss?.supported === false,
    "prerequisite-loss runtime selection must fail closed to unsupported",
  );
  assert(
    bootstrap.runtimeSelectionPrerequisiteLoss?.selectedLane === UNSUPPORTED_LANE,
    `prerequisite-loss runtime selection chose unexpected lane: ${bootstrap.runtimeSelectionPrerequisiteLoss?.selectedLane ?? "missing"}`,
  );
  assert(
    bootstrap.runtimeSelectionPrerequisiteLoss?.reasonCode === "missing_webassembly",
    `prerequisite-loss runtime selection reason mismatch: ${bootstrap.runtimeSelectionPrerequisiteLoss?.reasonCode ?? "missing"}`,
  );
  assert(
    bootstrap.runtimeSelectionPrerequisiteLoss?.outcome === null,
    `prerequisite-loss runtime selection must stay on the no-throw path, got ${bootstrap.runtimeSelectionPrerequisiteLoss?.outcome ?? "missing"}`,
  );
  assert(
    bootstrap.runtimeSelectionPrerequisiteLoss?.health?.status === "demoted",
    `prerequisite-loss runtime selection must preserve the stale demoted health snapshot, got ${bootstrap.runtimeSelectionPrerequisiteLoss?.health?.status ?? "missing"}`,
  );
  assert(
    bootstrap.runtimeSelectionPrerequisiteLoss?.health?.lastTrigger === "worker_bootstrap_timeout",
    `prerequisite-loss runtime selection must preserve the stale worker_bootstrap_timeout trigger, got ${bootstrap.runtimeSelectionPrerequisiteLoss?.health?.lastTrigger ?? "missing"}`,
  );
  assert(
    bootstrap.runtimeSelectionPrerequisiteLoss?.health?.demotedToLaneId === UNSUPPORTED_LANE,
    `prerequisite-loss runtime selection must preserve fail-closed demoted lane ${UNSUPPORTED_LANE}, got ${bootstrap.runtimeSelectionPrerequisiteLoss?.health?.demotedToLaneId ?? "missing"}`,
  );
  assert(
    prerequisiteLossCandidate?.reasonCode === "candidate_prerequisite_missing",
    "prerequisite-loss candidate matrix must preserve candidate_prerequisite_missing for the worker lane",
  );
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
    bootstrap.storageExercise?.subviewWriteCompacted === true,
    "worker storage exercise must compact typed-array subviews before IndexedDB writes",
  );
  assert(
    bootstrap.storageExercise?.subviewStoredBackingBytes === 2,
    `worker storage subview backing must retain exactly 2 bytes, got ${bootstrap.storageExercise?.subviewStoredBackingBytes ?? "missing"}`,
  );
  assert(
    bootstrap.storageExercise?.legacySubviewRawBackingObserved === true,
    "worker storage exercise must inject and observe an oversized legacy DataView backing",
  );
  assert(
    bootstrap.storageExercise?.legacySubviewReadCompacted === true,
    "worker storage exercise must compact legacy typed-array subviews on IndexedDB reads",
  );
  assert(
    bootstrap.storageExercise?.spoofedSubviewWriteCompacted === true,
    "worker storage exercise must ignore typed-array subclass view accessors",
  );
  assert(
    bootstrap.storageExercise?.shadowedSubviewWriteCompacted === true,
    "worker storage exercise must ignore shadowed typed-array view properties",
  );
  assert(
    bootstrap.storageExercise?.proxiedSubviewFailedClosed === true,
    "worker storage exercise must reject proxied typed-array views without writing",
  );
  assert(
    bootstrap.storageExercise?.fullArrayBufferStoredExactly === true,
    "worker storage exercise must preserve full-span ArrayBuffer bytes",
  );
  assert(
    bootstrap.storageExercise?.fullUint8ArrayStoredExactly === true,
    "worker storage exercise must preserve full-span Uint8Array bytes",
  );
  assert(
    bootstrap.storageExercise?.dataViewWriteCompacted === true,
    "worker storage exercise must compact DataView backing bytes",
  );
  assert(
    bootstrap.storageExercise?.spoofedDataViewWriteCompacted === true,
    "worker storage exercise must ignore DataView subclass accessors",
  );
  assert(
    bootstrap.storageExercise?.emptySubviewWriteCompacted === true,
    "worker storage exercise must compact empty subviews to empty backing",
  );
  assert(
    bootstrap.artifactExercise?.artifactSubviewStoredCompacted === true,
    "worker artifact retention must store only logical typed-array subview bytes",
  );
  assert(
    bootstrap.artifactExercise?.artifactSubviewStoredBackingBytes === 2,
    `worker artifact subview backing must retain exactly 2 bytes, got ${bootstrap.artifactExercise?.artifactSubviewStoredBackingBytes ?? "missing"}`,
  );
  assert(
    bootstrap.artifactExercise?.artifactSubviewExportCompacted === true,
    "worker artifact export must not retain bytes outside persisted typed-array subviews",
  );
  assert(
    bootstrap.artifactExercise?.downloadFailureCode === "ASUPERSYNC_BROWSER_ARTIFACT_DOWNLOAD_UNSUPPORTED",
    `unexpected worker artifact download failure code: ${bootstrap.artifactExercise?.downloadFailureCode ?? "missing"}`,
  );
  assert(
    bootstrap.artifactExercise?.quotaFailureReason === "quota_exceeded",
    `unexpected worker artifact quota failure reason: ${bootstrap.artifactExercise?.quotaFailureReason ?? "missing"}`,
  );
  assert(
    bootstrap.artifactExercise?.quotaSubviewStoredCompacted === true,
    "worker artifact quota accounting must match physical retained subview bytes",
  );
  assert(
    bootstrap.artifactExercise?.quotaReportedLogicalBytes === true,
    "worker artifact quota accounting must report exactly 600 logical bytes",
  );
  assert(
    bootstrap.artifactExercise?.quotaSubviewStoredBackingBytes === 600,
    `worker quota subview backing must retain exactly 600 bytes, got ${bootstrap.artifactExercise?.quotaSubviewStoredBackingBytes ?? "missing"}`,
  );

  const scenarioInventory = buildScenarioInventory(
    bootstrap,
    preferredCandidate,
    prerequisiteLossCandidate,
    parsed,
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
    retrying_status: bootstrap.laneHealthRetrying.status,
    retrying_selected_lane: bootstrap.executionLadderRetrying.selectedLane,
    retrying_last_trigger: bootstrap.laneHealthRetrying.lastTrigger,
    retrying_retry_budget_remaining: bootstrap.laneHealthRetrying.retryBudgetRemaining,
    demotion_status: bootstrap.laneHealthDemotion.status,
    demotion_failure_count: bootstrap.laneHealthDemotion.failureCount,
    demotion_retry_budget_remaining: bootstrap.laneHealthDemotion.retryBudgetRemaining,
    demotion_cooldown_until_ms: bootstrap.laneHealthDemotion.cooldownUntilMs,
    demotion_last_trigger: bootstrap.laneHealthDemotion.lastTrigger,
    demotion_demoted_to_lane_id: bootstrap.laneHealthDemotion.demotedToLaneId,
    demoted_selected_lane: bootstrap.runtimeSelectionDemoted.selectedLane,
    demoted_reason_code: bootstrap.runtimeSelectionDemoted.reasonCode,
    demoted_outcome: bootstrap.runtimeSelectionDemoted.outcome,
    demoted_health_last_trigger: bootstrap.runtimeSelectionDemoted.health.lastTrigger,
    demoted_health_demoted_to_lane_id:
      bootstrap.runtimeSelectionDemoted.health.demotedToLaneId,
    demoted_worker_candidate_reason: preferredCandidate?.reasonCode ?? null,
    prerequisite_loss_simulated: bootstrap.prerequisiteLossSimulation?.simulated ?? false,
    prerequisite_loss_skipped_reason:
      bootstrap.prerequisiteLossSimulation?.skippedReason ?? null,
    prerequisite_loss_selected_lane:
      bootstrap.runtimeSelectionPrerequisiteLoss?.selectedLane ?? null,
    prerequisite_loss_reason_code:
      bootstrap.runtimeSelectionPrerequisiteLoss?.reasonCode ?? null,
    prerequisite_loss_health_status:
      bootstrap.runtimeSelectionPrerequisiteLoss?.health?.status ?? null,
    prerequisite_loss_health_last_trigger:
      bootstrap.runtimeSelectionPrerequisiteLoss?.health?.lastTrigger ?? null,
    prerequisite_loss_health_demoted_to_lane_id:
      bootstrap.runtimeSelectionPrerequisiteLoss?.health?.demotedToLaneId ?? null,
    prerequisite_loss_worker_candidate_reason:
      prerequisiteLossCandidate?.reasonCode ?? null,
    recovered_status: bootstrap.laneHealthReset.status,
    recovered_selected_lane: bootstrap.runtimeSelectionRecovered.selectedLane,
    recovered_outcome: bootstrap.runtimeSelectionRecovered.outcome,
    storage_backend: bootstrap.storageExercise?.backend ?? null,
    artifact_download_failure_code: bootstrap.artifactExercise?.downloadFailureCode ?? null,
    quota_failure_reason: bootstrap.artifactExercise?.quotaFailureReason ?? null,
    scenario_inventory: scenarioInventory,
    artifacts: buildArtifacts(url),
  };
} catch (error) {
  caughtError = error;
  result = {
    status: "error",
    url,
    executable_path: executablePath,
    message: error instanceof Error ? error.message : String(error),
    scenario_inventory: [],
    artifacts: buildArtifacts(url),
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
