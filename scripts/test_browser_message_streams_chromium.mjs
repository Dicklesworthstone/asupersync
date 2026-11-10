/**
 * Browser-native message receivers against Chromium and the actual SDK modules.
 * TypeScript is transpiled in memory; browser-core JS/WASM is the checked-in
 * artifact. This does not rebuild Rust or certify a newly built npm package.
 * Run: node scripts/test_browser_message_streams_chromium.mjs
 * Set ASUPERSYNC_MESSAGE_TEST_REF to a commit SHA for a source negative control.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createRequire, stripTypeScriptTypes } from "node:module";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const root = fileURLToPath(new URL("../", import.meta.url));
const sourceRef = process.env.ASUPERSYNC_MESSAGE_TEST_REF;
if (sourceRef && !/^[0-9a-f]{40}$/.test(sourceRef)) {
  throw new Error("ASUPERSYNC_MESSAGE_TEST_REF must be a full commit SHA");
}
const source = (name) => sourceRef
  ? execFileSync("git", ["show", `${sourceRef}:${name}`], { cwd: root, maxBuffer: 8 * 1024 * 1024 })
  : readFileSync(new URL(`../${name}`, import.meta.url));
let playwright;
try { playwright = createRequire(import.meta.url)("playwright-core"); }
catch (error) {
  const modules = process.env.CODEX_PRIMARY_RUNTIME_NODE_MODULES;
  if (!modules) throw error;
  playwright = createRequire(`${modules}/package.json`)("playwright-core");
}

const routes = new Map();
const hashes = {};
for (const name of ["index", "fetch"]) {
  const path = `packages/browser/src/${name}.ts`;
  const input = source(path);
  hashes[path] = createHash("sha256").update(input).digest("hex");
  routes.set(`/sdk/${name}.js`, {
    type: "text/javascript", body: stripTypeScriptTypes(input.toString(), { mode: "transform" }),
  });
}
for (const name of ["index.js", "asupersync.js", "webtransport-streams.js", "asupersync_bg.wasm"]) {
  const path = `packages/browser-core/${name}`;
  const input = source(path);
  hashes[path] = createHash("sha256").update(input).digest("hex");
  routes.set(`/core/${name}`, {
    type: name.endsWith(".wasm") ? "application/wasm" : "text/javascript", body: input,
  });
}
routes.set("/", { type: "text/html", body: `<!doctype html><html><head>
<script type="importmap">{"imports":{
"@asupersync/browser":"/sdk/index.js",
"@asupersync/browser-core":"/core/index.js",
"@asupersync/browser-core/webtransport-streams":"/core/webtransport-streams.js"
}}</script></head><body>Browser message receiver regression</body></html>` });

const server = createServer((request, response) => {
  const route = routes.get(new URL(request.url, "http://127.0.0.1").pathname);
  response.writeHead(route ? 200 : 404, {
    "content-type": route?.type ?? "text/plain",
    "cache-control": "no-store",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-embedder-policy": "require-corp",
  });
  response.end(route?.body ?? "Not found");
});
let browser;
try {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  browser = await playwright.chromium.launch({
    executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH ?? "/usr/bin/chromium",
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });
  const page = await browser.newPage();
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  const results = await page.evaluate(async () => {
    const sdk = await import("@asupersync/browser");
    const capability = { capabilityGranted: true, redactionPolicy: "metadata_only" };
    const rows = [];
    const check = (condition, message) => { if (!condition) throw new Error(message); };
    const reason = async (promise, expected) => {
      try { await promise; throw new Error(`expected rejection ${expected}`); }
      catch (error) {
        check(error.code === "ASUPERSYNC_BROWSER_MESSAGE_STREAM_FAILED", `wrong error code: ${error.code}`);
        check(error.reason === expected, `wrong error reason: ${error.reason}`);
      }
    };
    const refused = (operation, expected) => {
      try { operation(); throw new Error(`expected refusal ${expected}`); }
      catch (error) { check(error.reason === expected, `wrong refusal: ${error.reason}`); }
    };
    async function run(name, test) {
      let timer;
      try {
        await Promise.race([test(), new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error("scenario timed out")), 5000);
        })]);
        rows.push({ name, passed: true });
      } catch (error) { rows.push({ name, passed: false, error: String(error) }); }
      finally { clearTimeout(timer); }
    }
    await run("message_channel_fifo_and_transfer", async () => {
      const pair = sdk.createBrowserMessageChannel({ capability });
      try {
        const stream = pair.port2.receiveStream({ maxQueuedMessages: 4 });
        const first = stream.next();
        pair.port1.send({ sequence: 1 });
        const bytes = new Uint8Array([7, 8, 9]);
        pair.port1.send(bytes.buffer, [bytes.buffer]);
        check(bytes.byteLength === 0, "the actual host must transfer the buffer");
        const one = await first;
        const two = await stream.next();
        check(!one.done && one.value.sequence === 1, "first message order");
        check(!two.done && [...new Uint8Array(two.value)].join() === "7,8,9", "transferred bytes");
        await stream.return();
        await stream.closed;
        check(stream.queuedMessages === 0 && stream.state === "closed", "receiver cleanup");
      } finally { pair.close(); }
    });
    await run("bounded_overflow_closes_receiver", async () => {
      const pair = sdk.createBrowserMessageChannel({ capability });
      try {
        const stream = pair.port2.receiveStream({ maxQueuedMessages: 2 });
        pair.port1.send(1); pair.port1.send(2); pair.port1.send(3);
        await reason(stream.closed, "message_limit_exceeded");
        await reason(stream.next(), "message_limit_exceeded");
        check(stream.queuedMessages === 0 && stream.state === "errored", "overflow retains no payloads");
      } finally { pair.close(); }
    });
    await run("abort_settles_parked_receive", async () => {
      const pair = sdk.createBrowserMessageChannel({ capability });
      try {
        const controller = new AbortController();
        const stream = pair.port2.receiveStream({ signal: controller.signal });
        const pending = reason(stream.next(), "aborted");
        const closed = reason(stream.closed, "aborted");
        controller.abort();
        await Promise.all([pending, closed]);
        check(stream.state === "cancelled" && stream.queuedMessages === 0, "abort cleanup");
      } finally { pair.close(); }
    });
    await run("source_close_settles_parked_receive", async () => {
      const pair = sdk.createBrowserMessageChannel({ capability });
      try {
        const stream = pair.port2.receiveStream();
        const pending = stream.next();
        pair.port2.close();
        check((await pending).done, "source close must finish the pending receive");
        await stream.closed;
      } finally { pair.close(); }
    });
    await run("exclusive_receive_and_pending_bound", async () => {
      const pair = sdk.createBrowserMessageChannel({ capability });
      try {
        const stream = pair.port2.receiveStream();
        refused(() => pair.port2.receiveStream(), "receiver_in_use");
        refused(() => pair.port2.takeMessages(), "receiver_in_use");
        refused(() => pair.port2.onMessage(() => {}), "receiver_in_use");
        refused(() => pair.port2.detach(), "receiver_in_use");
        const pending = stream.next();
        await reason(stream.next(), "receive_in_progress");
        pair.port1.send("one-owner");
        check((await pending).value === "one-owner", "first receiver keeps ownership");
        await stream.return();
      } finally { pair.close(); }
    });
    await run("broadcast_channel_native_delivery", async () => {
      const name = `asupersync-stream-${crypto.randomUUID()}`;
      const sender = sdk.createBrowserBroadcastChannel(name, { capability });
      const receiver = sdk.createBrowserBroadcastChannel(name, { capability });
      try {
        const stream = receiver.receiveStream({ maxQueuedMessages: 2 });
        const pending = stream.next();
        sender.post({ sequence: 5 });
        check((await pending).value.sequence === 5, "broadcast message delivered");
        await stream.return();
        await stream.closed;
      } finally { sender.close(); receiver.close(); }
    });
    await run("async_iteration_break_releases_endpoint", async () => {
      const pair = sdk.createBrowserMessageChannel({ capability });
      try {
        const stream = pair.port2.receiveStream();
        pair.port1.send("stop");
        for await (const value of stream) {
          check(value === "stop", "iterator value");
          break;
        }
        await stream.closed;
        check(pair.port2.state === "closed" && stream.queuedMessages === 0, "break closes owned endpoint");
      } finally { pair.close(); }
    });
    return rows;
  });
  console.log(JSON.stringify({
    scenario: "browser-message-streams-chromium", browser: browser.version(), source_ref: sourceRef ?? "working-tree",
    evidence: "actual Chromium MessageChannel/BroadcastChannel and SDK source; checked-in browser-core artifacts, no Rust rebuild",
    source_sha256: hashes, results, page_errors: pageErrors,
  }, null, 2));
  assert.equal(results.length, 7);
  assert.deepEqual(results.filter((row) => !row.passed), []);
  assert.deepEqual(pageErrors, []);
} finally {
  await browser?.close();
  await new Promise((resolve) => server.close(resolve));
}
