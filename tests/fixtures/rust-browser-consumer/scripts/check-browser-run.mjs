import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { chromium } from "playwright-core";

const distDir = path.resolve("dist");
const outputPath = process.argv[2] ? path.resolve(process.argv[2]) : null;
const REQUIRED_EVENT_SYMBOLS = ["task_spawn", "task_join", "task_cancel"];

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
  if (
    relative.startsWith("..") ||
    path.isAbsolute(relative)
  ) {
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
  if (parsed.diagnostics_clean !== true) {
    throw new Error("fixture diagnostics were not clean");
  }
  assert(parsed.ready_phase === "ready", `expected ready_phase=ready, got ${parsed.ready_phase ?? "missing"}`);
  assert(
    parsed.disposed_phase === "disposed",
    `expected disposed_phase=disposed, got ${parsed.disposed_phase ?? "missing"}`,
  );
  assert(
    parsed.child_scope_count_before_unmount === 1,
    `expected exactly one child scope before unmount, got ${parsed.child_scope_count_before_unmount ?? "missing"}`,
  );
  assert(
    parsed.active_task_count_before_unmount === 1,
    `expected exactly one active task before unmount, got ${parsed.active_task_count_before_unmount ?? "missing"}`,
  );
  assert(
    parsed.completed_task_outcome === "ok",
    `expected completed_task_outcome=ok, got ${parsed.completed_task_outcome ?? "missing"}`,
  );
  assert(
    parsed.cancel_event_count === 1,
    `expected cancel_event_count=1, got ${parsed.cancel_event_count ?? "missing"}`,
  );
  assert(
    Number.isInteger(parsed.dispatch_count) && parsed.dispatch_count >= 6,
    `expected dispatch_count >= 6, got ${parsed.dispatch_count ?? "missing"}`,
  );
  assert(
    Array.isArray(parsed.event_symbols),
    "fixture must report event_symbols as an array",
  );
  for (const symbol of REQUIRED_EVENT_SYMBOLS) {
    assert(
      parsed.event_symbols.includes(symbol),
      `fixture event log missing required symbol: ${symbol}`,
    );
  }
  assert(
    parsed.capabilities?.has_window === true,
    "fixture must confirm browser window capability availability",
  );
  assert(
    parsed.capabilities?.has_document === true,
    "fixture must confirm browser document capability availability",
  );
  assert(
    parsed.capabilities?.has_webassembly === true,
    "fixture must confirm browser WebAssembly capability availability",
  );

  result = {
    status: "ok",
    url,
    executable_path: executablePath,
    scenario_id: parsed.scenario_id,
    support_lane: parsed.support_lane,
    diagnostics_clean: parsed.diagnostics_clean,
    ready_phase: parsed.ready_phase,
    disposed_phase: parsed.disposed_phase,
    child_scope_count_before_unmount: parsed.child_scope_count_before_unmount,
    active_task_count_before_unmount: parsed.active_task_count_before_unmount,
    completed_task_outcome: parsed.completed_task_outcome,
    cancel_event_count: parsed.cancel_event_count,
    dispatch_count: parsed.dispatch_count,
    event_symbols: parsed.event_symbols,
    capabilities: parsed.capabilities,
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
