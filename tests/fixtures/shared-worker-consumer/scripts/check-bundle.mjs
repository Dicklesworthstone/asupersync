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
    if (
      resolved.endsWith(".js")
      || resolved.endsWith(".mjs")
      || resolved.endsWith(".ts")
    ) {
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

const jsAssets = collectJsFiles(distDir);
if (jsAssets.length < 2) {
  throw new Error(
    `Expected at least two JS assets in dist for page + shared worker bundles, got ${jsAssets.length}`,
  );
}

let sawBaselineMarker = false;
let sawReuseMarker = false;
let sawProtocolMismatchMarker = false;
let sawCrashFallbackMarker = false;
let sawAttachMarker = false;
let sawTopologyMarker = false;
let sawCoordinatorProtocolMismatchMarker = false;
let sawCoordinatorCrashMarker = false;
let sawCoordinatorDetachMarker = false;

for (const assetPath of jsAssets) {
  const content = fs.readFileSync(assetPath, "utf8");
  sawBaselineMarker ||= content.includes("shared-worker-selection-baseline");
  sawReuseMarker ||= content.includes("shared-worker-selection-reuse");
  sawProtocolMismatchMarker ||= content.includes(
    "shared-worker-selection-protocol-mismatch",
  );
  sawCrashFallbackMarker ||= content.includes(
    "shared-worker-selection-crash-fallback",
  );
  sawAttachMarker ||= content.includes("shared-worker-coordinator-attach");
  sawTopologyMarker ||= content.includes(
    "shared-worker-coordinator-topology-snapshot",
  );
  sawCoordinatorProtocolMismatchMarker ||= content.includes(
    "shared-worker-coordinator-protocol-mismatch",
  );
  sawCoordinatorCrashMarker ||= content.includes(
    "shared-worker-coordinator-crash-before-handshake",
  );
  sawCoordinatorDetachMarker ||= content.includes("shared-worker-coordinator-detach");
}

if (!sawBaselineMarker) {
  throw new Error("Built bundle must retain the shared-worker-selection-baseline marker");
}

if (!sawReuseMarker) {
  throw new Error("Built bundle must retain the shared-worker-selection-reuse marker");
}

if (!sawProtocolMismatchMarker) {
  throw new Error(
    "Built bundle must retain the shared-worker-selection-protocol-mismatch marker",
  );
}

if (!sawCrashFallbackMarker) {
  throw new Error(
    "Built bundle must retain the shared-worker-selection-crash-fallback marker",
  );
}

if (!sawAttachMarker) {
  throw new Error("Built bundle must retain the shared-worker-coordinator-attach marker");
}

if (!sawTopologyMarker) {
  throw new Error(
    "Built bundle must retain the shared-worker-coordinator-topology-snapshot marker",
  );
}

if (!sawCoordinatorProtocolMismatchMarker) {
  throw new Error(
    "Built bundle must retain the shared-worker-coordinator-protocol-mismatch marker",
  );
}

if (!sawCoordinatorCrashMarker) {
  throw new Error(
    "Built bundle must retain the shared-worker-coordinator-crash-before-handshake marker",
  );
}

if (!sawCoordinatorDetachMarker) {
  throw new Error(
    "Built bundle must retain the shared-worker-coordinator-detach marker",
  );
}

console.log(
  JSON.stringify(
    {
      status: "ok",
      jsAssetCount: jsAssets.length,
      sawBaselineMarker,
      sawReuseMarker,
      sawProtocolMismatchMarker,
      sawCrashFallbackMarker,
      sawAttachMarker,
      sawTopologyMarker,
      sawCoordinatorProtocolMismatchMarker,
      sawCoordinatorCrashMarker,
      sawCoordinatorDetachMarker,
    },
    null,
    2,
  ),
);
