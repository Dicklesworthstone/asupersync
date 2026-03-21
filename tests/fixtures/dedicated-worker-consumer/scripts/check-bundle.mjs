import fs from "node:fs";
import path from "node:path";

const distDir = path.resolve("dist");
const indexPath = path.join(distDir, "index.html");
const assetDir = path.join(distDir, "assets");

if (!fs.existsSync(distDir)) {
  throw new Error(`Missing dist directory: ${distDir}`);
}

if (!fs.existsSync(indexPath)) {
  throw new Error(`Missing built index.html: ${indexPath}`);
}

if (!fs.existsSync(assetDir)) {
  throw new Error(`Missing assets directory: ${assetDir}`);
}

const jsAssets = fs
  .readdirSync(assetDir)
  .filter((name) => name.endsWith(".js") || name.endsWith(".mjs"));
if (jsAssets.length < 2) {
  throw new Error(
    `Expected at least two JS assets in dist/assets for main-thread + worker bundles, got ${jsAssets.length}`,
  );
}

let sawBootstrapMarker = false;
let sawShutdownMarker = false;
let sawRuntimeSelectionBaselineMarker = false;
let sawScopeSelectionBaselineMarker = false;
let sawScopeSelectionPreferredMainThreadMarker = false;
let sawLaneHealthRetryingMarker = false;
let sawExecutionLadderRetryingMarker = false;
let sawLaneHealthDemotionMarker = false;
let sawRuntimeSelectionDemotedMarker = false;
let sawRuntimeSelectionPrerequisiteLossMarker = false;
let sawLaneHealthResetMarker = false;
let sawRuntimeSelectionRecoveredMarker = false;
let sawStorageSupportMarker = false;
let sawStorageRoundtripMarker = false;
let sawStorageArtifactMarker = false;
let sawDownloadUnsupportedMarker = false;
let sawArtifactExportMarker = false;
let sawArtifactDownloadGuardMarker = false;
let sawArtifactQuotaGuardMarker = false;
let sawArtifactCleanupMarker = false;
for (const assetName of jsAssets) {
  const content = fs.readFileSync(path.join(assetDir, assetName), "utf8");
  sawBootstrapMarker ||= content.includes("worker-bootstrap");
  sawShutdownMarker ||= content.includes("worker-shutdown-complete");
  sawRuntimeSelectionBaselineMarker ||= content.includes("worker-runtime-selection-baseline");
  sawScopeSelectionBaselineMarker ||= content.includes("worker-scope-selection-baseline");
  sawScopeSelectionPreferredMainThreadMarker ||= content.includes(
    "worker-scope-selection-preferred-main-thread",
  );
  sawLaneHealthRetryingMarker ||= content.includes("worker-lane-health-retrying");
  sawExecutionLadderRetryingMarker ||= content.includes("worker-execution-ladder-retrying");
  sawLaneHealthDemotionMarker ||= content.includes("worker-lane-health-demotion");
  sawRuntimeSelectionDemotedMarker ||= content.includes("worker-runtime-selection-demoted");
  sawRuntimeSelectionPrerequisiteLossMarker ||= content.includes(
    "worker-runtime-selection-prerequisite-loss",
  );
  sawLaneHealthResetMarker ||= content.includes("worker-lane-health-reset");
  sawRuntimeSelectionRecoveredMarker ||= content.includes("worker-runtime-selection-recovered");
  sawStorageSupportMarker ||= content.includes("worker-storage-support");
  sawStorageRoundtripMarker ||= content.includes("worker-storage-roundtrip");
  sawStorageArtifactMarker ||= content.includes("worker-storage-artifact-export-handoff");
  sawDownloadUnsupportedMarker ||= content.includes(
    "ASUPERSYNC_BROWSER_ARTIFACT_DOWNLOAD_UNSUPPORTED",
  );
  sawArtifactExportMarker ||= content.includes("worker-artifact-archive");
  sawArtifactDownloadGuardMarker ||= content.includes("worker-artifact-download-unavailable");
  sawArtifactQuotaGuardMarker ||= content.includes("worker-artifact-quota-guard");
  sawArtifactCleanupMarker ||= content.includes("worker-artifact-cleanup");
}

if (!sawBootstrapMarker) {
  throw new Error("Built worker bundle must retain the worker-bootstrap message marker");
}

if (!sawShutdownMarker) {
  throw new Error(
    "Built worker bundle must retain the worker-shutdown-complete message marker",
  );
}

if (!sawRuntimeSelectionBaselineMarker) {
  throw new Error("Built worker bundle must retain the worker-runtime-selection-baseline marker");
}

if (!sawScopeSelectionBaselineMarker) {
  throw new Error("Built worker bundle must retain the worker-scope-selection-baseline marker");
}

if (!sawScopeSelectionPreferredMainThreadMarker) {
  throw new Error(
    "Built worker bundle must retain the worker-scope-selection-preferred-main-thread marker",
  );
}

if (!sawLaneHealthDemotionMarker) {
  throw new Error("Built worker bundle must retain the worker-lane-health-demotion marker");
}

if (!sawLaneHealthRetryingMarker) {
  throw new Error("Built worker bundle must retain the worker-lane-health-retrying marker");
}

if (!sawRuntimeSelectionDemotedMarker) {
  throw new Error("Built worker bundle must retain the worker-runtime-selection-demoted marker");
}

if (!sawRuntimeSelectionPrerequisiteLossMarker) {
  throw new Error(
    "Built worker bundle must retain the worker-runtime-selection-prerequisite-loss marker",
  );
}

if (!sawExecutionLadderRetryingMarker) {
  throw new Error("Built worker bundle must retain the worker-execution-ladder-retrying marker");
}

if (!sawLaneHealthResetMarker) {
  throw new Error("Built worker bundle must retain the worker-lane-health-reset marker");
}

if (!sawRuntimeSelectionRecoveredMarker) {
  throw new Error("Built worker bundle must retain the worker-runtime-selection-recovered marker");
}

if (!sawStorageArtifactMarker) {
  throw new Error("Built worker bundle must retain the storage/artifact exercise marker");
}

if (!sawDownloadUnsupportedMarker) {
  throw new Error("Built worker bundle must retain the worker download failure code marker");
}

if (!sawStorageSupportMarker) {
  throw new Error("Built worker bundle must retain the worker-storage-support marker");
}

if (!sawStorageRoundtripMarker) {
  throw new Error("Built worker bundle must retain the worker-storage-roundtrip marker");
}

if (!sawArtifactExportMarker) {
  throw new Error("Built worker bundle must retain the worker-artifact-archive marker");
}

if (!sawArtifactDownloadGuardMarker) {
  throw new Error(
    "Built worker bundle must retain the worker-artifact-download-unavailable marker",
  );
}

if (!sawArtifactQuotaGuardMarker) {
  throw new Error("Built worker bundle must retain the worker-artifact-quota-guard marker");
}

if (!sawArtifactCleanupMarker) {
  throw new Error("Built worker bundle must retain the worker-artifact-cleanup marker");
}

console.log(
  JSON.stringify(
    {
      status: "ok",
      jsAssetCount: jsAssets.length,
      sawBootstrapMarker,
      sawShutdownMarker,
      sawRuntimeSelectionBaselineMarker,
      sawScopeSelectionBaselineMarker,
      sawScopeSelectionPreferredMainThreadMarker,
      sawLaneHealthDemotionMarker,
      sawRuntimeSelectionDemotedMarker,
      sawRuntimeSelectionPrerequisiteLossMarker,
      sawLaneHealthResetMarker,
      sawRuntimeSelectionRecoveredMarker,
      sawStorageSupportMarker,
      sawStorageRoundtripMarker,
      sawStorageArtifactMarker,
      sawDownloadUnsupportedMarker,
      sawArtifactExportMarker,
      sawArtifactDownloadGuardMarker,
      sawArtifactQuotaGuardMarker,
      sawArtifactCleanupMarker,
    },
    null,
    2,
  ),
);
