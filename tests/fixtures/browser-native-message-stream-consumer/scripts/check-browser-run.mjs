import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { chromium } from "playwright-core";

const distDir = path.resolve("dist");
const outputPath = process.argv[2] ? path.resolve(process.argv[2]) : null;
const requiredFields = [
  "bead_id",
  "scenario_id",
  "host_context",
  "api_surface",
  "capability_granted",
  "degraded_mode",
  "bytes_sent",
  "bytes_received",
  "messages_sent",
  "messages_received",
  "close_kind",
  "expected_error",
  "actual_error",
  "verdict",
  "first_failure",
];
const requiredScenarios = [
  "message_channel_text_roundtrip",
  "message_channel_bytes_roundtrip",
  "message_port_close_rejects_send",
  "message_port_abort_is_sticky",
  "broadcast_channel_delivery",
  "readable_stream_bytes",
  "writable_stream_bytes",
  "capability_denied",
  "degraded_mode_denied",
];

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
      return parsed.phase === "complete" || parsed.phase === "error";
    } catch {
      return false;
    }
  });

  const statusText = await page.locator("#status").textContent();
  if (!statusText) {
    throw new Error("fixture completed without status text");
  }
  const parsed = JSON.parse(statusText);
  if (parsed.phase === "error") {
    throw new Error(parsed.first_failure ?? parsed.error_message ?? "fixture error");
  }
  return parsed;
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
  const page = await context.newPage();
  const baseUrl = `http://127.0.0.1:${serverHandle.port}`;
  await page.goto(`${baseUrl}/index.html`, { waitUntil: "domcontentloaded" });
  const state = await waitForFixtureState(page);
  const rows = Array.isArray(state.rows) ? state.rows : [];
  const scenarioIds = rows.map((row) => row.scenario_id);
  const missingScenarios = requiredScenarios.filter(
    (scenarioId) => !scenarioIds.includes(scenarioId),
  );
  const failingRows = rows.filter((row) => row.verdict !== "pass");
  const missingFieldRows = rows.flatMap((row) =>
    requiredFields
      .filter((field) => !(field in row))
      .map((field) => `${row.scenario_id ?? "unknown"}:${field}`),
  );

  assert(state.validation_passed === true, "fixture validation_passed must be true");
  assert(missingScenarios.length === 0, `missing scenarios: ${missingScenarios.join(", ")}`);
  assert(failingRows.length === 0, `failing rows: ${JSON.stringify(failingRows)}`);
  assert(missingFieldRows.length === 0, `rows missing fields: ${missingFieldRows.join(", ")}`);

  result = {
    status: "ok",
    scenario_id: "BROWSER-NATIVE-MESSAGE-STREAM-CONSUMER",
    bead_id: "asupersync-41hk0t",
    browser_version: browser.version(),
    fixture_path: "tests/fixtures/browser-native-message-stream-consumer",
    required_fields: requiredFields,
    required_scenarios: requiredScenarios,
    missing_scenarios: missingScenarios,
    row_count: rows.length,
    rows,
  };
} catch (error) {
  caughtError = error;
  result = {
    status: "error",
    scenario_id: "BROWSER-NATIVE-MESSAGE-STREAM-CONSUMER",
    bead_id: "asupersync-41hk0t",
    error_message: error instanceof Error ? error.message : String(error),
  };
} finally {
  if (browser) {
    await browser.close();
  }
  if (serverHandle) {
    await new Promise((resolve) => serverHandle.server.close(resolve));
  }
  writeResult(result);
}

if (caughtError) {
  throw caughtError;
}

console.log(JSON.stringify(result, null, 2));
