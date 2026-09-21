import fs from "node:fs";
import path from "node:path";

const distDir = path.resolve("dist");

function collectJsFiles(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const resolved = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectJsFiles(resolved));
      continue;
    }
    if (resolved.endsWith(".js") || resolved.endsWith(".mjs")) {
      files.push(resolved);
    }
  }
  return files;
}

if (!fs.existsSync(distDir)) {
  throw new Error(`Missing dist directory: ${distDir}`);
}

const indexPath = path.join(distDir, "index.html");
if (!fs.existsSync(indexPath)) {
  throw new Error(`Missing built index.html: ${indexPath}`);
}

const serviceWorkerPath = path.join(distDir, "service-worker.js");
if (!fs.existsSync(serviceWorkerPath)) {
  throw new Error(`Missing built service-worker.js: ${serviceWorkerPath}`);
}

const jsAssets = collectJsFiles(distDir);
if (jsAssets.length < 2) {
  throw new Error(
    `Expected at least two JS assets in dist for page + service worker bundles, got ${jsAssets.length}`,
  );
}

let sawBootstrapMarker = false;
let sawRegistrationMarker = false;
let sawWorkMarker = false;
let sawHandoffMarker = false;
let sawReopenMarker = false;
let sawMismatchMarker = false;
let sawCleanupMarker = false;
let sawDirectRuntimeReasonMarker = false;

for (const assetPath of jsAssets) {
  const content = fs.readFileSync(assetPath, "utf8");
  sawBootstrapMarker ||= content.includes("service-worker-broker-bootstrap");
  sawRegistrationMarker ||= content.includes("service-worker-broker-registration");
  sawWorkMarker ||= content.includes("service-worker-broker-work");
  sawHandoffMarker ||= content.includes("service-worker-broker-handoff");
  sawReopenMarker ||= content.includes("service-worker-broker-reopen");
  sawMismatchMarker ||= content.includes("service-worker-broker-mismatch");
  sawCleanupMarker ||= content.includes("service-worker-broker-cleanup");
  sawDirectRuntimeReasonMarker ||= content.includes("service_worker_direct_runtime_not_shipped");
}

if (!sawBootstrapMarker) {
  throw new Error("Built bundle must retain the service-worker-broker-bootstrap marker");
}

if (!sawRegistrationMarker) {
  throw new Error("Built bundle must retain the service-worker-broker-registration marker");
}

if (!sawWorkMarker) {
  throw new Error("Built bundle must retain the service-worker-broker-work marker");
}

if (!sawHandoffMarker) {
  throw new Error("Built bundle must retain the service-worker-broker-handoff marker");
}

if (!sawReopenMarker) {
  throw new Error("Built bundle must retain the service-worker-broker-reopen marker");
}

if (!sawMismatchMarker) {
  throw new Error("Built bundle must retain the service-worker-broker-mismatch marker");
}

if (!sawCleanupMarker) {
  throw new Error("Built bundle must retain the service-worker-broker-cleanup marker");
}

if (!sawDirectRuntimeReasonMarker) {
  throw new Error("Built bundle must retain the service_worker_direct_runtime_not_shipped marker");
}

console.log(
  JSON.stringify(
    {
      status: "ok",
      jsAssetCount: jsAssets.length,
      sawBootstrapMarker,
      sawRegistrationMarker,
      sawWorkMarker,
      sawHandoffMarker,
      sawReopenMarker,
      sawMismatchMarker,
      sawCleanupMarker,
      sawDirectRuntimeReasonMarker,
    },
    null,
    2,
  ),
);
